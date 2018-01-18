REGISTRY = {}

def register_event(event_cls):
    REGISTRY[event_cls._type] = event_cls

class MetaRegistry(type):

    def __new__(cls, name, bases, attrs):
        event_cls = type.__new__(cls, name, bases, attrs)
        register_event(event_cls)
        return event_cls

class Event(object):
    __metaclass__ = MetaRegistry

    _type = None

    def call(self):
        pass

    @staticmethod
    def from_dict(d):
        return REGISTRY[d['event_type']].from_dict(d)

    def to_dict(self):
        return {
            'type': 'event',
            'event_type': self._type
        }
