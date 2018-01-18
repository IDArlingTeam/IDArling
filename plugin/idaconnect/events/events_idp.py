import idc

from events import Event

class UndefinedEvent(Event):
    _type = 'undefined'

    def __init__(self, ea):
        super(UndefinedEvent, self).__init__()
        self._ea = ea

    def call(self):
        idc.del_items(self._ea)

    @staticmethod
    def from_dict(d):
        return UndefinedEvent(d['ea'])

    def to_dict(self):
        return dict(super(UndefinedEvent, self).to_dict(), **{
            'ea': self._ea
        })
