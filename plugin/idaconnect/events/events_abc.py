from ..shared.packets import Packet, EventBase

# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------


class EventMeta(type):
    _REGISTRY = {}

    @staticmethod
    def newCls(newType):
        return EventMeta._REGISTRY[newType]

    def __new__(cls, name, bases, attrs):
        newCls = type.__new__(cls, name, bases, attrs)
        EventMeta._REGISTRY[newCls.TYPE] = newCls
        return newCls


class Event(EventBase):
    __metaclass__ = EventMeta

    TYPE = None

    @staticmethod
    def new(dct):
        eventCls = EventMeta.newCls(dct['event_type'])
        del dct['type']
        del dct['event_type']
        return eventCls(**dct)

    @staticmethod
    def isEvent(dct):
        return EventBase.isEvent(dct)

    def __init__(self):
        super(Event, self).__init__()
        self['event_type'] = self.TYPE

    def __call__(self):
        # Events must implement this method
        raise NotImplementedError('call method not implemented')
