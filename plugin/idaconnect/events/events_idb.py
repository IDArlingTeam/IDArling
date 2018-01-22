import logging

import idc
import idaapi
import ida_funcs
import ida_name
import ida_enum

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

    def __init__(self, ea, flags, size, tid):
        super(MakeDataEvent, self).__init__()
        self['ea'] = ea
        self['flags'] = flags
        self['size'] = size
        self['tid'] = tid

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
        flags = ida_name.SN_LOCAL if self['local_name'] else 0
        idc.set_name(self['ea'], self['new_name'], flags | ida_name.SN_NOWARN)


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

    def __init__(self, start_ea, new_start):
        super(SetFuncStartEvent, self).__init__()
        self['start_ea'] = start_ea
        self['new_start'] = new_start

    def __call__(self):
        ida_funcs.set_func_start(self['start_ea'], self['new_start'])


class SetFuncEndEvent(Event):
    TYPE = 'set_func_end'

    def __init__(self, start_ea, new_end):
        super(SetFuncEndEvent, self).__init__()
        self['start_ea'] = start_ea
        self['new_end'] = new_end

    def __call__(self):
        ida_funcs.set_func_end(self['start_ea'], self['new_end'])


class CmtChangedEvent(Event):
    TYPE = 'cmt_changed'

    def __init__(self, ea, comment, rptble):
        super(CmtChangedEvent, self).__init__()
        self['ea'] = ea
        self['comment'] = comment
        self['rptble'] = rptble

    def __call__(self):
        idc.set_cmt(self['ea'], self['comment'], self['rptble'])


class TiChangedEvent(Event):
    TYPE = 'ti_changed'

    def __init__(self, ea, py_type):
        super(TiChangedEvent, self).__init__()
        self['ea'] = ea
        self['py_type'] = py_type

    def __call__(self):
        idc.apply_type(self['ea'], self['py_type'])


class OpTypeChangedEvent(Event):
    TYPE = 'op_type_changed'

    def __init__(self, ea, n, op):
        super(OpTypeChangedEvent, self).__init__()
        self['ea'] = ea
        self['n'] = n
        self['op'] = op

    def __call__(self):
        if self['op'] == 'hex':
            idc.op_hex(self['ea'], self['n'])
        if self['op'] == 'bin':
            idc.op_bin(self['ea'], self['n'])
        if self['op'] == 'dec':
            idc.op_dec(self['ea'], self['n'])
        if self['op'] == 'chr':
            idc.op_chr(self['ea'], self['n'])
        if self['op'] == 'oct':
            idc.op_oct(self['ea'], self['n'])


class EnumCreatedEvent(Event):
    TYPE = 'enum_created'

    def __init__(self, enum, name):
        super(EnumCreatedEvent, self).__init__()
        self['enum'] = enum
        self['name'] = name

    def __call__(self):
        idc.add_enum(self['enum'], self['name'], 0)


class EnumDeletedEvent(Event):
    TYPE = 'enum_deleted'

    def __init__(self, enum):
        super(EnumDeletedEvent, self).__init__()
        self['enum'] = enum

    def __call__(self):
        idc.del_enum(self['enum'])


class EnumRenamedEvent(Event):
    TYPE = 'enum_renamed'

    def __init__(self, tid, new_name):
        super(EnumRenamedEvent, self).__init__()
        self['tid'] = tid
        self['new_name'] = new_name

    def __call__(self):
        idaapi.set_enum_name(self['tid'], self['new_name'])


class EnumBfChangedEvent(Event):
    TYPE = 'enum_bf_changed'

    def __init__(self, tid, bf_flag):
        super(EnumBfChangedEvent, self).__init__()
        self['tid'] = tid
        self['bf_flag'] = bf_flag

    def __call__(self):
        ida_enum.set_enum_bf(self['tid'], self['bf_flag'])
