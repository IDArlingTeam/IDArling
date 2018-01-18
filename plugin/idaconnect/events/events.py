class MetaRegistry(type):
    REGISTRY = {}

    def __new__(cls, name, bases, attrs):
        event_cls = type.__new__(cls, name, bases, attrs)
        MetaRegistry.REGISTRY[event_cls._type] = event_cls
        return event_cls


class Event(dict):
    __metaclass__ = MetaRegistry

    _type = None

    @staticmethod
    def new(dct):
        del dct['type']
        event_cls = MetaRegistry.REGISTRY[dct['event_type']]
        del dct['event_type']
        return event_cls(**dct)

    def __init__(self):
        super(Event, self).__init__()
        self['type'] = 'event'
        self['event_type'] = self._type

    def __call__(self):
        raise NotImplementedError('call not implemented')
