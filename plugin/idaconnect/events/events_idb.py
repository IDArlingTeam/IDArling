import idc

from events import Event


class MakeCodeEvent(Event):
    _type = 'make_code'

    def __init__(self, ea):
        super(MakeCodeEvent, self).__init__()
        self['ea'] = ea

    def __call__(self):
        idc.create_insn(self['ea'])


class MakeDataEvent(Event):
    _type = 'make_data'

    def __init__(self, ea, flags, tid, size):
        super(MakeDataEvent, self).__init__()
        self['ea'] = ea
        self['flags'] = flags
        self['tid'] = tid
        self['size'] = size

    def __call__(self):
        idc.create_data(self['ea'], self['flags'], self['size'], self['tid'])
