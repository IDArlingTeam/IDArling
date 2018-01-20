from ..util.misc import makeMetaClass

REGISTRY = {}


class Event(dict):
    __metaclass__ = makeMetaClass(REGISTRY)

    _type = None

    @staticmethod
    def new(dct):
        del dct['type']
        eventCls = REGISTRY[dct['event_type']]
        del dct['event_type']
        event = eventCls(**dct)
        return event

    def __init__(self):
        super(Event, self).__init__()
        self['type'] = 'event'
        self['event_type'] = self._type

    def __call__(self):
        raise NotImplementedError('call not implemented')
