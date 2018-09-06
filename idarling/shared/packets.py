# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import collections
import itertools


def with_metaclass(meta, *bases):
    """Python 2 and 3 compatible way to add a meta-class."""

    class Metaclass(type):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)

        @classmethod
        def __prepare__(cls, name, _):
            return meta.__prepare__(name, bases)

    return type.__new__(Metaclass, "temporary_class", (), {})


class Serializable(object):
    """
    This base class for an object than can be serialized. More specifically,
    such objects can be read from and written into a Python dictionary.
    """

    @classmethod
    def new(cls, dct):
        """Creates a new instance of the object."""
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        """Writes the object into the dictionary."""
        pass

    def parse(self, dct):
        """Reads the object from the dictionary."""
        pass


class Default(Serializable):
    """This object will be serialized using its attributes dictionary."""

    @staticmethod
    def attrs(dct):
        """
        Get a filtered version of an attributes dictionary. This method
        currently simply removes the private attributes of the object.
        """
        return {
            key: val for key, val in dct.items() if not key.startswith("_")
        }

    def build_default(self, dct):
        """Write the object to the dictionary."""
        dct.update(Default.attrs(self.__dict__))

    def parse_default(self, dct):
        """Read the object from the dictionary."""
        self.__dict__.update(Default.attrs(dct))


class PacketFactory(type):
    """
    A metaclass that is used to register new packet classes as they are being
    defined, and instantiate new packets from their name when necessary.
    """

    _PACKETS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        """Register a new packet class into the factory."""
        cls = super(PacketFactory, mcs).__new__(mcs, name, bases, attrs)
        if (
            cls.__type__ is not None
            and cls.__type__ not in PacketFactory._PACKETS
        ):
            PacketFactory._PACKETS[cls.__type__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):  # noqa: N804
        """
        Instantiate the packet corresponding to the serialized dictionary. It
        will check if the packet type is registered, the deferred the
        request to the specialized packet factory.
        """
        cls = PacketFactory._PACKETS[dct["type"]]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Packet(with_metaclass(PacketFactory, Serializable)):
    """
    The base class for every packet received. Currently, the packet can
    only be of two kinds: either it is an event or a command.
    """

    __type__ = None

    def __init__(self):
        super(Packet, self).__init__()
        assert self.__type__ is not None, "__type__ not implemented"

    @staticmethod
    def parse_packet(dct, server=False):
        """Parse the packet from a dictionary."""
        cls = PacketFactory.get_class(dct, server)
        packet = cls.new(dct)
        if isinstance(packet, Reply):
            packet.trigger_initback()
        return packet

    def build_packet(self):
        """Build the packet into a dictionary."""
        dct = collections.defaultdict(collections.defaultdict)
        self.build(dct)
        return dct

    def __repr__(self):
        """
        Return a textual representation of a packet. Currently, it is only
        used to pretty-print the packet contents into the console.
        """
        name = self.__class__.__name__
        if isinstance(self, Query) or isinstance(self, Reply):
            name = self.__parent__.__name__ + "." + name
        attrs = [
            u"{}={}".format(k, v)
            for k, v in Default.attrs(self.__dict__).items()
        ]
        return u"{}({})".format(name, u", ".join(attrs))


class PacketDeferred(object):
    """
    An Twisted-like deferred object that supports a standard callback, as well
    as a new callback triggered when the expected packet is being instantiated.
    """

    def __init__(self):
        super(PacketDeferred, self).__init__()
        self._errback = None

        self._callback = None
        self._callresult = None
        self._called = False

        self._initback = None
        self._initresult = None
        self._inited = False

    def add_callback(self, callback):
        """Register a callback for this deferred."""
        self._callback = callback
        if self._called:
            self._run_callback()
        return self

    def add_errback(self, errback):
        """Register an errback for this deferred."""
        self._errback = errback
        return self

    def add_initback(self, initback):
        """Register an initback for this deferred."""
        self._initback = initback
        if self._inited:
            self._run_initback()
        return self

    def callback(self, result):
        """Trigger the callback function."""
        if self._called:
            raise RuntimeError("Callback already triggered")
        self._called = True
        self._callresult = result
        self._run_callback()

    def initback(self, result):
        """Trigger the initback function."""
        if self._inited:
            raise RuntimeError("Initback already triggered")
        self._inited = True
        self._initresult = result
        self._run_initback()

    def _run_callback(self):
        """Internal method that calls the callback/errback function."""
        if self._callback:
            try:
                self._callback(self._callresult)
            except Exception as e:
                self._errback(e)

    def _run_initback(self):
        """Internal method that call the initback/errback function."""
        if self._initback:
            try:
                self._initback(self._initresult)
            except Exception as e:
                self._errback(e)


class EventFactory(PacketFactory):
    """A packet factory specialized for event packets."""

    _EVENTS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(EventFactory, mcs).__new__(mcs, name, bases, attrs)
        if (
            cls.__event__ is not None
            and cls.__event__ not in EventFactory._EVENTS
        ):
            EventFactory._EVENTS[cls.__event__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):  # noqa: N804
        if server:  # Server only knows about DefaultEvent
            return DefaultEvent

        cls = EventFactory._EVENTS[dct["event_type"]]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Event(with_metaclass(EventFactory, Packet)):
    """Base class for all events. They have a subtype and a tick count."""

    __type__ = "event"
    __event__ = None

    def __init__(self):
        super(Event, self).__init__()
        assert self.__event__ is not None, "__event__ not implemented"
        self._tick = 0

    @property
    def tick(self):
        """Get the tick count."""
        return self._tick

    @tick.setter
    def tick(self, tick):
        """Set the tick count."""
        self._tick = tick

    def build(self, dct):
        dct["type"] = self.__type__
        dct["event_type"] = self.__event__
        dct["tick"] = self._tick
        self.build_event(dct)
        return dct

    def parse(self, dct):
        self._tick = dct.pop("tick")
        self.parse_event(dct)
        return self

    def build_event(self, dct):
        """Build the event into a dictionary."""
        pass

    def parse_event(self, dct):
        """Parse the event from a dictionary."""
        pass


class DefaultEvent(Default, Event):
    """
    This is a class that should be subclassed for events that can be serialized
    from their attributes (which should be almost all of them).
    """

    def build_event(self, dct):
        self.build_default(dct)

    def parse_event(self, dct):
        self.parse_default(dct)


class CommandFactory(PacketFactory):
    """A packet factory specialized for commands packets."""

    _COMMANDS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(CommandFactory, mcs).__new__(mcs, name, bases, attrs)
        if (
            cls.__command__ is not None
            and cls.__command__ not in CommandFactory._COMMANDS
        ):
            # Does this command have a query and a reply
            if issubclass(cls, ParentCommand):
                # Register the query
                cls.Query.__parent__ = cls
                cls.Query.__command__ = cls.__command__ + "_query"
                CommandFactory._COMMANDS[cls.Query.__command__] = cls.Query

                # Register the reply
                cls.Reply.__parent__ = cls
                cls.Reply.__command__ = cls.__command__ + "_reply"
                CommandFactory._COMMANDS[cls.Reply.__command__] = cls.Reply
            else:
                CommandFactory._COMMANDS[cls.__command__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):  # noqa: N804
        cls = CommandFactory._COMMANDS[dct["command_type"]]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Command(with_metaclass(CommandFactory, Packet)):
    """Base class for all commands. Commands have a subtype."""

    __type__ = "command"
    __command__ = None

    def __init__(self):
        super(Command, self).__init__()
        assert self.__command__ is not None, "__command__ not implemented"

    def build(self, dct):
        dct["type"] = self.__type__
        dct["command_type"] = self.__command__
        self.build_command(dct)
        return dct

    def parse(self, dct):
        self.parse_command(dct)
        return self

    def build_command(self, dct):
        """Build a command into a dictionary."""
        pass

    def parse_command(self, dct):
        """Parse a command from a dictionary."""
        pass


class DefaultCommand(Default, Command):
    """
    This is a class that should be subclassed for events that can be serialized
    from their attributes (which is way rarer than for events).
    """

    def build_command(self, dct):
        self.build_default(dct)

    def parse_command(self, dct):
        self.parse_default(dct)


class ParentCommand(Command):
    """
    This class is used to define a command that expects an answer. Basically,
    it should subclass this class, and define two instance attributes Query and
    Reply that should themselves subclass packets.Query and packets.Reply.
    """

    __callbacks__ = {}
    Query, Reply = None, None


class Query(Packet):
    """A query is a packet sent that will expect to received a reply."""

    __parent__ = None

    _NEXT_ID = itertools.count()

    def __init__(self):
        super(Query, self).__init__()
        self._id = Query._NEXT_ID.next()

    @property
    def id(self):
        """Get the query identifier."""
        return self._id

    def build(self, dct):
        super(Query, self).build(dct)
        dct["__id__"] = self._id
        return dct

    def parse(self, dct):
        super(Query, self).parse(dct)
        self._id = dct["__id__"]
        return self

    def register_callback(self, d):
        """Register a callback triggered when the answer is received."""
        self.__parent__.__callbacks__[self._id] = d


class Reply(Packet):
    """A reply is a packet sent when a query packet is received."""

    __parent__ = None

    def __init__(self, query):
        super(Reply, self).__init__()
        self._id = query.id

    @property
    def id(self):
        """Get the query identifier."""
        return self._id

    def build(self, dct):
        super(Reply, self).build(dct)
        dct["__id__"] = self._id
        return dct

    def parse(self, dct):
        super(Reply, self).parse(dct)
        self._id = dct["__id__"]
        return self

    def trigger_callback(self):
        """Trigger the finalization callback of the query."""
        d = self.__parent__.__callbacks__[self._id]
        d.callback(self)
        del self.__parent__.__callbacks__[self._id]

    def trigger_initback(self):
        """Trigger the initialization callback of the query."""
        d = self.__parent__.__callbacks__[self._id]
        d.initback(self)


class Container(Command):
    """
    Containers are a special kind of commands that will contain some raw data.
    This is useful for exchanging files as they don't have to be encoded.
    """

    @staticmethod
    def __new__(cls, *args, **kwargs):
        self = super(Container, cls).__new__(cls)
        self._upback = None
        self._downback = None
        return self

    def __init__(self):
        super(Container, self).__init__()
        self._size = 0
        self._content = None
        self._upback = None
        self._downback = None

    @property
    def content(self):
        """Get the raw content."""
        return self._content

    @content.setter
    def content(self, content):
        """Set the raw content."""
        self._content = content
        self._size = len(content)

    @property
    def size(self):
        """Get the content size."""
        return self._size

    @size.setter
    def size(self, size):
        """Set the content size."""
        self._size = size

    @property
    def upback(self):
        """Get the upload callback triggered when some data is sent."""
        return self._upback

    @upback.setter
    def upback(self, upback):
        """Set the upload callback triggered when some data is sent."""
        self._upback = upback

    @property
    def downback(self):
        """Get the download callback triggered when some data is received."""
        return self._downback

    @downback.setter
    def downback(self, downback):
        """Set the download callback triggered when some data is received."""
        self._downback = downback

    def build(self, dct):
        super(Container, self).build(dct)
        dct["__size__"] = len(self._content)
        return dct

    def parse(self, dct):
        self._size = dct["__size__"]
        super(Container, self).parse(dct)
        return self
