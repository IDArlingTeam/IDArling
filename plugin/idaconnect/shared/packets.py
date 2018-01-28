from collections import defaultdict

from twisted.internet import defer


class Serializable(object):
    """
    A base class for an object than can be serialized. More specifically,
    such objects can be read from and written into a Python dictionary.
    """

    @classmethod
    def new(cls, dct):
        """
        Create a new instance of an object.

        :param dict[str, object] dct: the dictionary
        :rtype: Serializable
        """
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        """
        Write the object into the dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        pass

    def parse(self, dct):
        """
        Read the object from the dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Serializable
        """
        pass


class Default(Serializable):
    """
    An object that is automatically serialized using its attributes dictionary.
    """

    @staticmethod
    def fields(dct):
        """
        Get a filtered version of an attributes dictionary. This method
        currently simply removes the private attributes of the object.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        return {key: val for key, val in dct.iteritems()
                if not key.startswith('_')}

    def build(self, dct):
        """
        Write the object into the dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        super(Default, self).build(dct)
        dct.update(Default.fields(self.__dict__))
        return dct

    def parse(self, dct):
        """
        Read the object from the dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Default
        """
        super(Default, self).build(dct)
        self.__dict__.update(Default.fields(dct))
        return self


class PacketFactory(type):
    """
    A factory class used to instantiate packets as the come from the network.
    """
    _PACKETS = {}

    @classmethod
    def getClass(mcs, dct):
        """
        Get the class corresponding to the given dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: type[Packet]
        """
        cls = mcs._PACKETS[dct['type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    # noinspection PyUnresolvedReferences
    def __new__(mcs, name, bases, attrs):
        """
        Register a new packet class in the factory.

        :param str name: the name of the new class
        :param tuple[type] bases: the base classes of the new class
        :param dict[str, object] attrs: the attributes of the new class
        :return: the newly created class
        :rtype: type[Packet]
        """
        cls = super(PacketFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__type__ is not None and cls.__type__ not in mcs._PACKETS:
            mcs._PACKETS[cls.__type__] = cls
        return cls


class Packet(Serializable):
    """
    The base class for every packet received. Currently, the packet can
    only be of two kinds: either it is an event or a command.
    """
    __metaclass__ = PacketFactory

    __type__ = None

    def __init__(self):
        """
        Initialize a packet.
        """
        super(Packet, self).__init__()
        assert self.__type__ is not None, "__type__ not implemented"

    @staticmethod
    def parsePacket(dct):
        """
        Parse a packet from a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Packet
        """
        cls = PacketFactory.getClass(dct)
        assert isinstance(cls, Packet.__class__)
        packet = cls.new(dct)
        if isinstance(packet, Reply):
            packet.triggerInitback()
        return packet

    def buildPacket(self):
        """
        Build a packet into a dictionary.

        :rtype: dict[str, object]
        """
        dct = defaultdict(defaultdict)
        self.build(dct)
        return dct

    def __repr__(self):
        """
        Return a textual representation of a packet. Currently, it is only
        used to pretty-print the packet's contents into the console.

        :rtype: str
        """
        s = ['{}={}'.format(k, v) for k, v
             in Default.fields(self.__dict__).iteritems()]
        return '{}({})'.format(self.__class__.__name__, ', '.join(s))


class AlreadyInitedError(Exception):
    """
    This exception is raised when the packed has already been initialized.
    """
    pass


class PacketDeferred(defer.Deferred, object):
    """
    An improved deferred object that supports a new callback, called initback,
    that is triggered when the expected object (a packet) is being initialized.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the packet deferred.

        :param list[object] args: the arguments
        :param dict[str, object] kwargs: the named arguments
        """
        super(PacketDeferred, self).__init__(*args, **kwargs)
        self._inited = False
        self._initback = None
        self._initresult = None

    def addInitback(self, initback, *args, **kwargs):
        """
        Register a callback to the initialization event.

        :param (Packet) -> None initback: the callback function
        :param list[object] args: the arguments of the callback
        :param dict[str, object] kwargs: the named arguments of the callback
        :rtype: PacketDeferred
        """
        self._initback = (initback, args, kwargs)
        if self._inited:
            self._runInitback()
        return self

    def initback(self, result):
        """
        Trigger the callback function for the initialization event.

        :param Packet result: the result
        """
        assert not isinstance(result, defer.Deferred)
        self._startRunInitback(result)

    def _startRunInitback(self, result):
        """
        This function guards the one below it.

        :param Packet result: the result
        """
        if self._inited:
            raise AlreadyInitedError()
        self._inited = True
        self._initresult = result
        self._runInitback()

    def _runInitback(self):
        """
        This function will actually trigger the callback.
        """
        # noinspection PyBroadException
        try:
            initback, args, kwargs = self._initback
            self._initresult = initback(self._initresult, *args, **kwargs)
        except Exception:  # noqa
            pass


class EventFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type event.
    """
    _EVENTS = {}

    @classmethod
    def getClass(mcs, dct):
        """
        Get the class corresponding to the given dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: type[Event]
        """
        try:
            cls = mcs._EVENTS[dct['event_type']]
        except KeyError:
            cls = AbstractEvent
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    # noinspection PyUnresolvedReferences
    def __new__(mcs, name, bases, attrs):
        """
        Register a new event class in the factory.

        :param str name: the name of the new class
        :param tuple[type] bases: the base classes of the new class
        :param dict[str, object] attrs: the attributes of the new class
        :return: the newly created class
        :rtype: type[Event]
        """
        cls = super(EventFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__event__ is not None and cls.__event__ not in mcs._EVENTS:
            mcs._EVENTS[cls.__event__] = cls
        return cls


class Event(Packet):
    """
    The base class of every packet of type event received.
    """
    __metaclass__ = EventFactory

    __type__ = 'event'
    __event__ = None

    def __init__(self):
        """
        Initialize an event.
        """
        super(Event, self).__init__()
        assert self.__event__ is not None, "__event__ not implemented"

    def build(self, dct):
        """
        Write an event into a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        dct['type'] = self.__type__
        dct['event_type'] = self.__event__
        self.buildEvent(dct)
        return dct

    def parse(self, dct):
        """
        Reads an event from a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Event
        """
        self.parseEvent(dct)
        return self

    def buildEvent(self, dct):
        """
        Event subclasses should implement this method.

        :param dict[str, object] dct: the dictionary
        """
        pass

    def parseEvent(self, dct):
        """
        Event subclasses should implement this method.

        :param dict[str, object] dct: the dictionary
        """
        pass

    def __call__(self):
        """
        Trigger the event. This will reproduce the action into IDA.
        """
        raise NotImplementedError("__call__() not implemented")


# noinspection PyAbstractClass
class DefaultEvent(Default, Event):
    """
    A mix-in class for events that can be serialized from their attributes.
    """
    pass


# noinspection PyAbstractClass
class AbstractEvent(Event):
    """
    A class to represent events as seen by the server. The server relays the
    events to the interested clients, it doesn't know to interpret them.
    """

    def buildEvent(self, dct):
        dct.update(self.__dict__)

    def parseEvent(self, dct):
        self.__dict__.update(dct)


class CommandFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type command.
    """
    _COMMANDS = {}

    @classmethod
    def getClass(mcs, dct):
        """
        Get the class corresponding to the given dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: type[Command]
        """
        cls = mcs._COMMANDS[dct['command_type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    # noinspection PyUnresolvedReferences
    def __new__(mcs, name, bases, attrs):
        """
        Register a new command class in the factory.

        :param str name: the name of the new class
        :param tuple[type] bases: the base classes of the new class
        :param dict[str, object] attrs: the attributes of the new class
        :return: the newly created class
        :rtype: type[Command]
        """
        cls = super(CommandFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__command__ is not None \
                and cls.__command__ not in mcs._COMMANDS:
            mcs._COMMANDS[cls.__command__] = cls
        return cls


class Command(Packet):
    """
    The base class of every packet of type command received.
    """
    __metaclass__ = CommandFactory

    __type__ = 'command'
    __command__ = None

    def __init__(self):
        """
        Initialize a command.
        """
        super(Command, self).__init__()
        assert self.__command__ is not None, "__command__ not implemented"

    def build(self, dct):
        """
        Write a command into a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        dct['type'] = self.__type__
        dct['command_type'] = self.__command__
        self.buildCommand(dct)
        return dct

    def parse(self, dct):
        """
        Reads a command from a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Command
        """
        self.parseCommand(dct)
        return self

    def buildCommand(self, dct):
        """
        Command subclasses should implement this method.

        :param dict[str, object] dct: the dictionary
        """
        pass

    def parseCommand(self, dct):
        """
        Command subclasses should implement this method.

        :param dict[str, object] dct: the dictionary
        """
        pass


class DefaultCommand(Default, Command):
    """
    A mix-in class for commands that can be serialized from their attributes.
    """
    pass


class Query(Packet):
    """
    A class that must be inherited by commands expecting a reply.
    """
    CALLBACKS = []

    @classmethod
    def registerCallback(cls, d):
        """
        Register a callback for when the corresponding reply will be received.

        :param PacketDeferred d: the deferred to use
        """
        cls.CALLBACKS.append(d)


class Reply(Packet):
    """
    A class that must be inherited by commands sent in response to a query.
    """
    __query__ = None

    def __init__(self):
        """
        Initialize a reply.
        """
        super(Reply, self).__init__()
        assert self.__query__ is not None, "__query__ not implemented"

    def triggerInitback(self):
        """
        Trigger the initialization callback of the corresponding query.
        """
        d = self.__query__.CALLBACKS[0]
        d.initback(self)

    def triggerCallback(self):
        """
        Trigger the finalization callback of the corresponding query.
        """
        d = self.__query__.CALLBACKS.pop(0)
        d.callback(self)


class Container(Packet):
    """
    A class that must be implemented by commands that will contain a raw
    stream of bytes (payload). In reality, the payload will follow the command.
    """

    def __new__(cls, *args, **kwargs):
        """
        Create a new instance of a container.

        :param list[object] args: the arguments
        :param dict[str, object] kwargs: the named arguments
        :rtype: Container
        """
        # noinspection PyArgumentList
        self = super(Container, cls).__new__(cls, *args, **kwargs)
        self._upback = None
        self._downback = None
        return self

    def __init__(self):
        """
        Initialize a container.
        """
        super(Container, self).__init__()
        self._size = 0
        self._content = None
        self._upback = None
        self._downback = None

    def __len__(self):
        """
        Return the size of the content.
        :rtype: int
        """
        return self._size

    def build(self, dct):
        """
        Write a container into a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: dict[str, object]
        """
        super(Container, self).build(dct)
        dct['__size__'] = len(self._content)
        return dct

    def parse(self, dct):
        """
        Reads a command from a dictionary.

        :param dict[str, object] dct: the dictionary
        :rtype: Container
        """
        self._size = dct['__size__']
        super(Container, self).parse(dct)
        return self

    @property
    def content(self):
        """
        Get the content of the packet.

        :rtype: str
        """
        return self._content

    @content.setter
    def content(self, content):
        """
        Set the content of the packet.

        :param str content: the content
        """
        self._content = content

    @property
    def upback(self):
        """
        Get the callback that will be called every time some data is sent.

        :rtype (int, int) -> None upback: the callback
        """
        return self._upback

    @upback.setter
    def upback(self, upback):
        """
        Set the callback that will be called every time some data is sent.

        :param (int, int) -> None upback: the callback
        """
        self._upback = upback

    @property
    def downback(self):
        """
        Get the callback that will be called every time some data is received.

        :rtype: (int, int) -> None downback: the callback
        """
        return self._downback

    @downback.setter
    def downback(self, downback):
        """
        Set the callback that will be called every time some data is received.

        :param (int, int) -> None downback: the callback
        """
        self._downback = downback
