# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import collections
import itertools

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

        :param dct: the dictionary
        :return: the object
        """
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        """
        Write the object into the dictionary.

        :param dct: the dictionary
        :return: the dictionary
        """
        pass

    def parse(self, dct):
        """
        Read the object from the dictionary.

        :param dct: the dictionary
        :return: the object
        """
        pass


class Default(Serializable):
    """
    An object that is automatically serialized using its attributes dictionary.
    """

    @staticmethod
    def attrs(dct):
        """
        Get a filtered version of an attributes dictionary. This method
        currently simply removes the private attributes of the object.

        :param dct: the dictionary
        :return: the filtered dictionary
        """
        return {key: val for key, val in dct.iteritems()
                if not key.startswith('_')}

    def buildDefault(self, dct):
        """
        Write the object to the dictionary using its attributes dictionary.

        :param dct: the dictionary
        """
        dct.update(Default.attrs(self.__dict__))

    def parseDefault(self, dct):
        """
        Read the object from the dictionary using its attributes dictionary.

        :param dct: the dictionary
        """
        self.__dict__.update(Default.attrs(dct))


class PacketFactory(type):
    """
    A factory class used to instantiate packets as they come from the network.
    """
    _PACKETS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        """
        Register a new packet class in the factory.

        :param name: the name of the new class
        :param bases: the base classes of the new class
        :param attrs: the attributes of the new class
        :return: the newly created class
        """
        cls = super(PacketFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__type__ is not None \
                and cls.__type__ not in PacketFactory._PACKETS:
            PacketFactory._PACKETS[cls.__type__] = cls
        return cls

    @classmethod
    def getClass(mcs, dct):
        """
        Get the class corresponding to the given dictionary.

        :param dct: the dictionary
        :return: the packet class
        """
        cls = PacketFactory._PACKETS[dct['type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
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

        :param dct: the dictionary
        :return: the packet
        """
        cls = PacketFactory.getClass(dct)
        packet = cls.new(dct)
        if isinstance(packet, Reply):
            packet.triggerInitback()
        return packet

    def buildPacket(self):
        """
        Build a packet into a dictionary.

        :return: the dictionary
        """
        dct = collections.defaultdict(collections.defaultdict)
        self.build(dct)
        return dct

    def __repr__(self):
        """
        Return a textual representation of a packet. Currently, it is only
        used to pretty-print the packet's contents into the console.

        :return: the representation
        """
        name = self.__class__.__name__
        if isinstance(self, Query) or isinstance(self, Reply):
            name = self.__parent__.__name__ + '.' + name
        attrs = ['{}={}'.format(k, v) for k, v
                 in Default.attrs(self.__dict__).iteritems()]
        return '{}({})'.format(name, ', '.join(attrs))


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

    def __init__(self, canceller=None):
        """
        Initialize the packet deferred.

        :param canceller: callable used to stop the pending operation
        """
        super(PacketDeferred, self).__init__(canceller)
        self._inited = False
        self._initback = None
        self._initresult = None

    def addInitback(self, initback):
        """
        Register a callback to the initialization event.

        :param initback: the callback function
        :return: the same object
        """
        self._initback = initback
        if self._inited:
            self._runInitback()
        return self

    def initback(self, result):
        """
        Trigger the callback function for the initialization event.

        :param result: the result
        """
        self._startRunInitback(result)

    def _startRunInitback(self, result):
        """
        This function guards the one below it.

        :param result: the result
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
        if self._initback:
            self._initback(self._initresult)


class EventFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type event.
    """
    _EVENTS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(EventFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__event__ is not None \
                and cls.__event__ not in EventFactory._EVENTS:
            EventFactory._EVENTS[cls.__event__] = cls
        return cls

    @classmethod
    def getClass(mcs, dct):
        cls = EventFactory._EVENTS[dct['event_type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls


class Event(Packet):
    """
    The base class of every packet of type event received.
    """
    __metaclass__ = EventFactory

    __type__ = 'event'
    __event__ = None

    def __init__(self):
        super(Event, self).__init__()
        assert self.__event__ is not None, "__event__ not implemented"
        self._tick = 0

    def build(self, dct):
        dct['type'] = self.__type__
        dct['event_type'] = self.__event__
        dct['tick'] = self._tick
        self.buildEvent(dct)
        return dct

    def parse(self, dct):
        self._tick = dct['tick']
        self.parseEvent(dct)
        return self

    def buildEvent(self, dct):
        """
        Event subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    def parseEvent(self, dct):
        """
        Event subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    @property
    def tick(self):
        """
        Get the tick of the event.

        :return: the tick
        """
        return self._tick

    @tick.setter
    def tick(self, tick):
        """
        Set the tick of the event.

        :param tick: the tick
        """
        self._tick = tick


class DefaultEvent(Default, Event):
    """
    A mix-in class for events that can be serialized from their attributes.
    """

    def buildEvent(self, dct):
        self.buildDefault(dct)

    def parseEvent(self, dct):
        self.parseDefault(dct)


class CommandFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type command.
    """
    _COMMANDS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(CommandFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__command__ is not None \
                and cls.__command__ not in CommandFactory._COMMANDS:
            if issubclass(cls, ParentCommand):
                cls.Query.__parent__ = cls
                cls.Query.__command__ = cls.__command__ + '_query'
                CommandFactory._COMMANDS[cls.Query.__command__] = cls.Query

                cls.Reply.__parent__ = cls
                cls.Reply.__command__ = cls.__command__ + '_reply'
                CommandFactory._COMMANDS[cls.Reply.__command__] = cls.Reply
            else:
                CommandFactory._COMMANDS[cls.__command__] = cls
        return cls

    @classmethod
    def getClass(mcs, dct):
        cls = CommandFactory._COMMANDS[dct['command_type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls


class Command(Packet):
    """
    The base class of every packet of type command received.
    """
    __metaclass__ = CommandFactory

    __type__ = 'command'
    __command__ = None

    def __init__(self):
        super(Command, self).__init__()
        assert self.__command__ is not None, "__command__ not implemented"

    def build(self, dct):
        dct['type'] = self.__type__
        dct['command_type'] = self.__command__
        self.buildCommand(dct)
        return dct

    def parse(self, dct):
        self.parseCommand(dct)
        return self

    def buildCommand(self, dct):
        """
        Command subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    def parseCommand(self, dct):
        """
        Command subclasses should implement this method.

        :param dct: the dictionary
        """
        pass


class DefaultCommand(Default, Command):
    """
    A mix-in class for commands that can be serialized from their attributes.
    """

    def buildCommand(self, dct):
        self.buildDefault(dct)

    def parseCommand(self, dct):
        self.parseDefault(dct)


class ParentCommand(Command):
    """
    An inner class that must used in order to link queries with replies.
    """
    __callbacks__ = {}
    Query, Reply = None, None


class Query(Packet):
    """
    A class that must be inherited by commands expecting a reply.
    """
    __parent__ = None

    _NEXT_ID = itertools.count()

    def __init__(self):
        """
        Initialize a query command.
        """
        super(Query, self).__init__()
        self._id = Query._NEXT_ID.next()

    def build(self, dct):
        super(Query, self).build(dct)
        dct['__id__'] = self._id
        return dct

    def parse(self, dct):
        super(Query, self).parse(dct)
        self._id = dct['__id__']
        return self

    @property
    def id(self):
        """
        Get the identifier of the query packet.

        :return: the id
        """
        return self._id

    def registerCallback(self, d):
        """
        Register a callback for when the corresponding reply will be received.

        :param: the deferred to use
        """
        self.__parent__.__callbacks__[self._id] = d


class Reply(Packet):
    """
    A class that must be inherited by commands sent in response to a query.
    """
    __parent__ = None

    def __init__(self, query):
        """
        Initialize a reply command.

        :param query: the query we're replying to
        """
        super(Reply, self).__init__()
        self._id = query.id

    def build(self, dct):
        super(Reply, self).build(dct)
        dct['__id__'] = self._id
        return dct

    def parse(self, dct):
        super(Reply, self).parse(dct)
        self._id = dct['__id__']
        return self

    @property
    def id(self):
        """
        Get the identifier of the reply packet.

        :return: the id
        """
        return self._id

    def triggerCallback(self):
        """
        Trigger the finalization callback of the corresponding query.
        """
        d = self.__parent__.__callbacks__[self._id]
        d.callback(self)
        del self.__parent__.__callbacks__[self._id]

    def triggerInitback(self):
        """
        Trigger the initialization callback of the corresponding query.
        """
        d = self.__parent__.__callbacks__[self._id]
        d.initback(self)


class Container(Command):
    """
    A class that must be implemented by commands that will contain a raw
    stream of bytes (payload). In reality, the payload will follow the command.
    """

    @staticmethod
    def __new__(cls, *args, **kwargs):
        """
        Create a new instance of a container.

        :return: the instance
        """
        self = super(Container, cls).__new__(cls)
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

        :return: the size
        """
        return self._size

    def build(self, dct):
        super(Container, self).build(dct)
        dct['__size__'] = len(self._content)
        return dct

    def parse(self, dct):
        self._size = dct['__size__']
        super(Container, self).parse(dct)
        return self

    @property
    def content(self):
        """
        Get the content of the packet.

        :return: the content
        """
        return self._content

    @content.setter
    def content(self, content):
        """
        Set the content of the packet.

        :param content: the content
        """
        self._content = content

    @property
    def upback(self):
        """
        Get the callback that will be called every time some data is sent.

        :return: the callback
        """
        return self._upback

    @upback.setter
    def upback(self, upback):
        """
        Set the callback that will be called every time some data is sent.

        :param upback: the callback
        """
        self._upback = upback

    @property
    def downback(self):
        """
        Get the callback that will be called every time some data is received.

        :return: the callback
        """
        return self._downback

    @downback.setter
    def downback(self, downback):
        """
        Set the callback that will be called every time some data is received.

        :param downback: the callback
        """
        self._downback = downback
