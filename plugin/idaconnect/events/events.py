class MetaRegistry(type):
    REGISTRY = {}

    def __new__(cls, name, bases, attrs):
        eventCls = type.__new__(cls, name, bases, attrs)
        MetaRegistry.REGISTRY[eventCls._type] = eventCls
        return eventCls


class Event(dict):
    __metaclass__ = MetaRegistry

    _type = None

    @staticmethod
    def new(dct):
        del dct['type']
        eventCls = MetaRegistry.REGISTRY[dct['event_type']]
        del dct['event_type']
        event = eventCls(**dct)
        return event

    def __init__(self):
        super(Event, self).__init__()
        self['type'] = 'event'
        self['event_type'] = self._type

    def __call__(self):
        raise NotImplementedError('call not implemented')
