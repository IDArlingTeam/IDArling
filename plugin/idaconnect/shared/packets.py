from collections import defaultdict

from twisted.internet import defer

# -----------------------------------------------------------------------------
# Serializable
# -----------------------------------------------------------------------------


class Serializable(object):

    @classmethod
    def new(cls, dct):
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        pass  # raise NotImplementedError("build() not implemented")

    def parse(self, dct):
        pass  # raise NotImplementedError("parse() not implemented")


class Default(Serializable):

    @staticmethod
    def fields(dct):
        return {key: val for key, val in dct.iteritems()
                if not key.startswith('_')}

    def build(self, dct):
        super(Default, self).build(dct)
        dct.update(Default.fields(self.__dict__))
        return dct

    def parse(self, dct):
        super(Default, self).build(dct)
        self.__dict__.update(Default.fields(dct))
        return self

# -----------------------------------------------------------------------------
# Packet
# -----------------------------------------------------------------------------


class PacketFactory(type):
    _PACKETS = {}

    @classmethod
    def getClass(mcs, dct):
        cls = mcs._PACKETS[dct['type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    def __new__(mcs, name, bases, attrs):
        cls = super(PacketFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__type__ is not None and cls.__type__ not in mcs._PACKETS:
            mcs._PACKETS[cls.__type__] = cls
        return cls


class Packet(Serializable):
    __metaclass__ = PacketFactory

    __type__ = None

    def __init__(self):
        super(Packet, self).__init__()
        assert self.__type__ is not None, "__type__ not implemented"

    @staticmethod
    def parsePacket(dct):
        cls = PacketFactory.getClass(dct)
        packet = cls.new(dct)
        if isinstance(packet, Reply):
            packet.triggerInitback()
        return packet

    def buildPacket(self):
        dct = defaultdict(defaultdict)
        self.build(dct)
        return dct

    def __repr__(self):
        s = ['{}={}'.format(k, v) for k, v
             in Default.fields(self.__dict__).iteritems()]
        return '{}({})'.format(self.__class__.__name__, ', '.join(s))

# -----------------------------------------------------------------------------
# Packet Deferred
# -----------------------------------------------------------------------------


class AlreadyInitedError(Exception):
    pass


class PacketDeferred(defer.Deferred, object):

    def __init__(self, *args, **kwargs):
        super(PacketDeferred, self).__init__(*args, **kwargs)
        self._inited = False
        self._initback = None
        self._initresult = None

    def addInitback(self, initback, *args, **kwargs):
        self._initback = (initback, args, kwargs)
        if self._inited:
            self._runInitback()
        return self

    def initback(self, result):
        assert not isinstance(result, defer.Deferred)
        self._startRunInitback(result)

    def _startRunInitback(self, result):
        if self._inited:
            raise AlreadyInitedError()
        self._inited = True
        self._initresult = result
        self._runInitback()

    def _runInitback(self):
        try:
            initback, args, kwargs = self._initback
            self._initresult = initback(self._initresult, *args, **kwargs)
        except:  # noqa
            pass

# -----------------------------------------------------------------------------
# Event
# -----------------------------------------------------------------------------


class EventFactory(PacketFactory):
    _EVENTS = {}

    @classmethod
    def getClass(mcs, dct):
        try:
            cls = mcs._EVENTS[dct['event_type']]
        except KeyError as e:
            cls = AbstractEvent
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    def __new__(mcs, name, bases, attrs):
        cls = super(EventFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__event__ is not None and cls.__event__ not in mcs._EVENTS:
            mcs._EVENTS[cls.__event__] = cls
        return cls


class Event(Packet):
    __metaclass__ = EventFactory

    __type__ = 'event'
    __event__ = None

    def __init__(self):
        super(Event, self).__init__()
        assert self.__event__ is not None, "__event__ not implemented"

    def build(self, dct):
        dct['type'] = self.__type__
        dct['event_type'] = self.__event__
        self.buildEvent(dct)
        return dct

    def parse(self, dct):
        self.parseEvent(dct)
        return self

    def buildEvent(self, dct):
        pass  # raise NotImplementedError("buildEvent() not implemented")

    def parseEvent(self, dct):
        pass  # raise NotImplementedError("parseEvent() not implemented")

    def __call__(self):
        raise NotImplementedError("__call__() not implemented")


class DefaultEvent(Default, Event):
    pass


class AbstractEvent(Event):

    def buildEvent(self, dct):
        dct.update(self.__dict__)

    def parseEvent(self, dct):
        self.__dict__.update(dct)


# -----------------------------------------------------------------------------
# Command
# -----------------------------------------------------------------------------


class CommandFactory(PacketFactory):
    _COMMANDS = {}

    @classmethod
    def getClass(mcs, dct):
        cls = mcs._COMMANDS[dct['command_type']]
        if cls.__metaclass__ != mcs:
            cls = cls.__metaclass__.getClass(dct)
        return cls

    def __new__(mcs, name, bases, attrs):
        cls = super(CommandFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__command__ is not None \
                and cls.__command__ not in mcs._COMMANDS:
            mcs._COMMANDS[cls.__command__] = cls
        return cls


class Command(Packet):
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
        pass  # raise NotImplementedError("buildCommand() not implemented")

    def parseCommand(self, dct):
        pass  # raise NotImplementedError("parseCommand() not implemented")


class DefaultCommand(Default, Command):
    pass

# -----------------------------------------------------------------------------
# Query
# -----------------------------------------------------------------------------


class Query(object):
    _CALLBACKS = []

    @classmethod
    def registerCallback(cls, d):
        cls._CALLBACKS.append(d)

# -----------------------------------------------------------------------------
# Reply
# -----------------------------------------------------------------------------


class Reply(object):
    __query__ = None

    def __init__(self):
        super(Reply, self).__init__()
        assert self.__query__ is not None, "__query__ not implemented"

    def triggerInitback(self):
        d = self.__query__._CALLBACKS[0]
        d.initback(self)

    def triggerCallback(self):
        d = self.__query__._CALLBACKS.pop(0)
        d.callback(self)

# -----------------------------------------------------------------------------
# Container
# -----------------------------------------------------------------------------


class Container(object):

    def __new__(cls, *args, **kwargs):
        self = super(Container, cls).__new__(cls, *args, **kwargs)
        self._upback = None
        self._downback = None
        return self

    def build(self, dct):
        super(Container, self).build(dct)
        dct['__size__'] = len(self._content)
        return dct

    def parse(self, dct):
        self.size = dct['__size__']
        super(Container, self).parse(dct)

    def getContent(self):
        return self._content

    def setContent(self, content):
        self._content = content

    def addUpback(self, upback):
        self._upback = upback

    def addDownback(self, downback):
        self._downback = downback
