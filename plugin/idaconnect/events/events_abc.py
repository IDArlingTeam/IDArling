from ..shared.packets import Packet

# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------


class EventMeta(type):
    REGISTRY = {}

    def __new__(cls, name, bases, attrs):
        newCls = type.__new__(cls, name, bases, attrs)
        EventMeta.REGISTRY[newCls._type] = newCls
        return newCls

    @staticmethod
    def newCls(newType):
        return EventMeta.REGISTRY[newType]


class Event(Packet):
    __metaclass__ = EventMeta

    _type = None

    @staticmethod
    def new(dct):
        eventCls = EventMeta.newCls(dct['event_type'])
        del dct['type']
        del dct['event_type']
        return eventCls(**dct)

    def __init__(self):
        super(Event, self).__init__('event')
        self['event_type'] = self._type

    def __call__(self):
        # Events must implement this method
        raise NotImplementedError('call method not implemented')
