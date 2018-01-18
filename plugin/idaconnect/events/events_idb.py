import idc

from events import Event


class MakeCodeEvent(Event):
    _type = 'makecode'

    def __init__(self, ea):
        super(MakeCodeEvent, self).__init__()
        self['ea'] = ea

    def __call__(self):
        idc.create_insn(self['ea'])
