import logging

import idc
import ida_funcs

from events_abc import Event


logger = logging.getLogger('IDAConnect.Events')

# -----------------------------------------------------------------------------
# IDB Events
# -----------------------------------------------------------------------------


class MakeCodeEvent(Event):
    TYPE = 'make_code'

    def __init__(self, ea):
        super(MakeCodeEvent, self).__init__()
        self['ea'] = ea

    def __call__(self):
        idc.create_insn(self['ea'])


class MakeDataEvent(Event):
    TYPE = 'make_data'

    def __init__(self, ea, flags, tid, size):
        super(MakeDataEvent, self).__init__()
        self['ea'] = ea
        self['flags'] = flags
        self['tid'] = tid
        self['size'] = size

    def __call__(self):
        idc.create_data(self['ea'], self['flags'], self['size'], self['tid'])


class RenamedEvent(Event):
    TYPE = 'renamed'

    def __init__(self, ea, new_name, local_name):
        super(RenamedEvent, self).__init__()
        self['ea'] = ea
        self['new_name'] = new_name
        self['local_name'] = local_name

    def __call__(self):
        idc.set_name(self['ea'], self['new_name'], self['local_name'])


class FuncAddedEvent(Event):
    TYPE = 'func_added'

    def __init__(self, start_ea, end_ea):
        super(FuncAddedEvent, self).__init__()
        self['start_ea'] = start_ea
        self['end_ea'] = end_ea

    def __call__(self):
        idc.add_func(self['start_ea'], self['end_ea'])


class DeletingFuncEvent(Event):
    TYPE = 'deleting_func'

    def __init__(self, start_ea):
        super(DeletingFuncEvent, self).__init__()
        self['start_ea'] = start_ea

    def __call__(self):
        idc.del_func(self['start_ea'])


class SetFuncStartEvent(Event):
    TYPE = 'set_func_start'

    def __init__(self, ea, new_ea):
        super(SetFuncStartEvent, self).__init__()
        self['ea'] = ea
        self['new_ea'] = new_ea

    def __call__(self):
        ida_funcs.set_func_start(self['ea'], self['new_ea'])


class SetFuncEndEvent(Event):
    TYPE = 'set_func_end'

    def __init__(self, ea, new_ea):
        super(SetFuncEndEvent, self).__init__()
        self['ea'] = ea
        self['new_ea'] = new_ea

    def __call__(self):
        ida_funcs.set_func_end(self['ea'], self['new_ea'])


class CmtChangedEvent(Event):
    TYPE = 'cmt_changed'

    def __init__(self, ea, repeatable_cmt, cmt):
        super(CmtChangedEvent, self).__init__()
        self['ea'] = ea
        self['repeatable_cmt'] = repeatable_cmt
        self['cmt'] = cmt

    def __call__(self):
        idc.set_cmt(self['ea'], self['cmt'], self['repeatable_cmt'])


class TiChangedEvent(Event):
    TYPE = 'ti_changed'

    def __init__(self, ea, t):
        super(TiChangedEvent, self).__init__()
        self['ea'] = ea
        self['t'] = t

    def __call__(self):
        idc.ApplyType(self['ea'], self['t'])


class OpTypeChangedEvent(Event):
    _type = 'op_ti_changed'

    def __init__(self, ea, n, flags, op):
        super(OpTypeChangedEvent, self).__init__()
        self['ea'] = ea
        self['n'] = n
        self['flags'] = flags
        self['op'] = op

    def __call__(self):
        if self['op'] == "hex":
            idc.op_hex(self['ea'], self['n'])
        if self['op'] == "bin":
            idc.op_bin(self['ea'], self['n'])
        if self['op'] == "dec":
            idc.op_dec(self['ea'], self['n'])
        if self['op'] == "chr":
            idc.op_chr(self['ea'], self['n'])
        if self['op'] == "oct":
            idc.op_oct(self['ea'], self['n'])
