import logging

import idc
import idaapi
import ida_funcs
import ida_name
import ida_enum

from ..shared.packets import Event, SimpleEvent


logger = logging.getLogger('IDAConnect.Core')

# -----------------------------------------------------------------------------
# IDB Events
# -----------------------------------------------------------------------------


class MakeCodeEvent(SimpleEvent):
    EVT_TYPE = 'make_code'

    def __init__(self, ea):
        super(MakeCodeEvent, self).__init__()
        self.ea = ea

    def __call__(self):
        idc.create_insn(self.ea)


class MakeDataEvent(SimpleEvent):
    EVT_TYPE = 'make_data'

    def __init__(self, ea, flags, size, tid):
        super(MakeDataEvent, self).__init__()
        self.ea = ea
        self.flags = flags
        self.size = size
        self.tid = tid

    def __call__(self):
        idc.create_data(self.ea, self.flags, self.size, self.tid)


class RenamedEvent(SimpleEvent):
    EVT_TYPE = 'renamed'

    def __init__(self, ea, new_name, local_name):
        super(RenamedEvent, self).__init__()
        self.ea = ea
        self.new_name = new_name
        self.local_name = local_name

    def __call__(self):
        flags = ida_name.SN_LOCAL if self.local_name else 0
        idc.set_name(self.ea, self.new_name, flags | ida_name.SN_NOWARN)


class FuncAddedEvent(SimpleEvent):
    EVT_TYPE = 'func_added'

    def __init__(self, start_ea, end_ea):
        super(FuncAddedEvent, self).__init__()
        self.start_ea = start_ea
        self.end_ea = end_ea

    def __call__(self):
        idc.add_func(self.start_ea, self.end_ea)


class DeletingFuncEvent(SimpleEvent):
    EVT_TYPE = 'deleting_func'

    def __init__(self, start_ea):
        super(DeletingFuncEvent, self).__init__()
        self.start_ea = start_ea

    def __call__(self):
        idc.del_func(self.start_ea)


class SetFuncStartEvent(SimpleEvent):
    EVT_TYPE = 'set_func_start'

    def __init__(self, start_ea, new_start):
        super(SetFuncStartEvent, self).__init__()
        self.start_ea = start_ea
        self.new_start = new_start

    def __call__(self):
        ida_funcs.set_func_start(self.start_ea, self.new_start)


class SetFuncEndEvent(SimpleEvent):
    EVT_TYPE = 'set_func_end'

    def __init__(self, start_ea, new_end):
        super(SetFuncEndEvent, self).__init__()
        self.start_ea = start_ea
        self.new_end = new_end

    def __call__(self):
        ida_funcs.set_func_end(self.start_ea, self.new_end)


class CmtChangedEvent(SimpleEvent):
    EVT_TYPE = 'cmt_changed'

    def __init__(self, ea, comment, rptble):
        super(CmtChangedEvent, self).__init__()
        self.ea = ea
        self.comment = comment
        self.rptble = rptble

    def __call__(self):
        idc.set_cmt(self.ea, self.comment, self.rptble)


class ExtraCmtChangedEvent(Event):
    EVT_TYPE = 'extra_cmt_changed'

    def __init__(self, ea, line_idx, cmt):
        super(ExtraCmtChangedEvent, self).__init__()
        self.ea = ea
        self.line_idx = line_idx
        self.cmt = cmt

    def __call__(self):
        idaapi.del_extra_cmt(self.ea, self.line_idx)
        isprev = 1 if self.line_idx - 1000 < 1000 else 0
        if not self.cmt:
            return 0
        idaapi.add_extra_cmt(self.ea, isprev, self.cmt)


class TiChangedEvent(SimpleEvent):
    EVT_TYPE = 'ti_changed'

    def __init__(self, ea, py_type):
        super(TiChangedEvent, self).__init__()
        self.ea = ea
        self.py_type = py_type

    def __call__(self):
        idc.apply_type(self.ea, self.py_type)


class OpTypeChangedEvent(SimpleEvent):
    EVT_TYPE = 'op_type_changed'

    def __init__(self, ea, n, op, extra):
        super(OpTypeChangedEvent, self).__init__()
        self.ea = ea
        self.n = n
        self.op = op
        self.extra = extra

    def __call__(self):
        if self.op == 'hex':
            idc.OpHex(self.ea, self.n)
        if self.op == 'bin':
            idc.OpBinary(self.ea, self.n)
        if self.op == 'dec':
            idc.OpDecimal(self.ea, self.n)
        if self.op == 'chr':
            idc.OpChr(self.ea, self.n)
        if self.op == 'oct':
            idc.OpOctal(self.ea, self.n)
        if self.op == 'enum':
            idc.OpEnumEx(self.ea, self.n, self.extra['id'],
                         self.extra['serial'])


class EnumCreatedEvent(SimpleEvent):
    EVT_TYPE = 'enum_created'

    def __init__(self, enum, name):
        super(EnumCreatedEvent, self).__init__()
        self.enum = enum
        self.name = name

    def __call__(self):
        idc.add_enum(self.enum, self.name, 0)


class EnumDeletedEvent(SimpleEvent):
    EVT_TYPE = 'enum_deleted'

    def __init__(self, enum):
        super(EnumDeletedEvent, self).__init__()
        self.enum = enum

    def __call__(self):
        idc.del_enum(self.enum)


class EnumRenamedEvent(SimpleEvent):
    EVT_TYPE = 'enum_renamed'

    def __init__(self, tid, new_name):
        super(EnumRenamedEvent, self).__init__()
        self.tid = tid
        self.new_name = new_name

    def __call__(self):
        idaapi.set_enum_name(self.tid, self.new_name)


class EnumBfChangedEvent(SimpleEvent):
    EVT_TYPE = 'enum_bf_changed'

    def __init__(self, tid, bf_flag):
        super(EnumBfChangedEvent, self).__init__()
        self.tid = tid
        self.bf_flag = bf_flag

    def __call__(self):
        ida_enum.set_enum_bf(self.tid, self.bf_flag)


class EnumCmtChangedEvent(SimpleEvent):
    EVT_TYPE = 'enum_cmt_changed'

    def __init__(self, tid, cmt, repeatable_cmt):
        super(EnumCmtChangedEvent, self).__init__()
        self.tid = tid
        self.cmt = cmt
        self.repeatable_cmt = repeatable_cmt

    def __call__(self):
        idaapi.set_enum_cmt(self.tid, self.cmt, self.repeatable_cmt)


class EnumMemberCreatedEvent(SimpleEvent):
    EVT_TYPE = 'enum_member_created'

    def __init__(self, id, name, value, bmask):
        super(EnumMemberCreatedEvent, self).__init__()
        self.id = id
        self.name = name
        self.value = value
        self.bmask = bmask

    def __call__(self):
        idaapi.add_enum_member(self.id, self.name, self.value, self.bmask)


class EnumMemberDeletedEvent(Event):
    EVT_TYPE = 'enum_member_deleted'

    def __init__(self, id, value, serial, bmask):
        super(EnumMemberDeletedEvent, self).__init__()
        self.id = id
        self.value = value
        self.serial = serial
        self.bmask = bmask

    def __call__(self):
        idaapi.del_enum_member(self.id, self.value, self.serial, self.bmask)


class StrucCreatedEvent(SimpleEvent):
    EVT_TYPE = 'struc_created'

    def __init__(self, struc, name, is_union):
        super(StrucCreatedEvent, self).__init__()
        self.struc = struc
        self.name = name
        self.is_union = is_union

    def __call__(self):
        idc.add_struc(self.struc, self.name, self.is_union)


class StrucDeletedEvent(SimpleEvent):
    EVT_TYPE = 'struc_deleted'

    def __init__(self, struc):
        super(StrucDeletedEvent, self).__init__()
        self.struc = struc

    def __call__(self):
        idc.del_struc(self.struc)


class StrucRenamedEvent(SimpleEvent):
    EVT_TYPE = 'struc_renamed'

    def __init__(self, sid, new_name):
        super(StrucRenamedEvent, self).__init__()
        self.sid = sid
        self.new_name = new_name

    def __call__(self):
        idaapi.set_struc_name(self.sid, self.new_name)


class StrucCmtChangedEvent(SimpleEvent):
    EVT_TYPE = 'struc_cmt_changed'

    def __init__(self, tid, cmt, repeatable_cmt):
        super(StrucCmtChangedEvent, self).__init__()
        self.tid = tid
        self.cmt = cmt
        self.repeatable_cmt = repeatable_cmt

    def __call__(self):
        idaapi.set_struc_cmt(self.tid, self.cmt, self.repeatable_cmt)


class StrucMemberCreatedEvent(SimpleEvent):
    EVT_TYPE = 'struc_member_created'

    def __init__(self, sid, fieldname, offset, flag, nbytes, extra):
        super(StrucMemberCreatedEvent, self).__init__()
        self.sid = sid
        self.fieldname = fieldname
        self.offset = offset
        self.flag = flag
        self.nbytes = nbytes
        self.extra = extra

    def __call__(self):
        mt = idaapi.opinfo_t()
        if idaapi.isStruct(self.flag):
            mt.tid = self.extra['id']
        if idaapi.isOff0(self.flag) or idaapi.isOff1(self.flag):
            mt.ri = idaapi.refinfo_t(self.extra['flags'], self.extra['base'],
                                     self.extra['target'],
                                     self.extra['tdelta'])
        if idaapi.isASCII(self.flag):
            mt.strtype = self.extra['strtype']
        sptr = idaapi.get_struc(self.sid)
        idaapi.add_struc_member(sptr, self.fieldname, self.offset,
                                self.flag, mt, self.nbytes)


class StrucMemberChangedEvent(SimpleEvent):
    EVT_TYPE = 'struc_member_changed'

    def __init__(self, sid, soff, eoff, flag, extra):
        super(StrucMemberChangedEvent, self).__init__()
        self.sid = sid
        self.soff = soff
        self.eoff = eoff
        self.flag = flag
        self.extra = extra

    def __call__(self):
        mt = idaapi.opinfo_t()
        if idaapi.isStruct(self.flag):
            mt.tid = self.extra['id']
        if idaapi.isOff0(self.flag) or idaapi.isOff1(self.flag):
            mt.ri = idaapi.refinfo_t(self.extra['flags'], self.extra['base'],
                                     self.extra['target'],
                                     self.extra['tdelta'])
        if idaapi.isASCII(self.flag):
            mt.strtype = self.extra['strtype']
        sptr = idaapi.get_struc(self.sid)
        idaapi.set_member_type(sptr, self.soff, self.flag,
                               mt, self.eoff - self.soff)


class StrucMemberDeletedEvent(SimpleEvent):
    EVT_TYPE = 'struc_member_deleted'

    def __init__(self, sid, offset):
        self.sid = sid
        self.offset = offset

    def __call__(self):
        sptr = idaapi.get_struc(self.sid)
        idaapi.del_struc_member(sptr, self.offset)


class ExpandingStrucEvent(SimpleEvent):
    EVT_TYPE = 'expanding_struc'

    def __init__(self, sid, offset, delta):
        self.sid = sid
        self.offset = offset
        self.delta = delta

    def __call__(self):
        sptr = idaapi.get_struc(self.sid)
        idaapi.expand_struc(sptr, self.offset, self.delta)


# -----------------------------------------------------------------------------
# IDP Events
# -----------------------------------------------------------------------------


class UndefinedEvent(SimpleEvent):
    EVT_TYPE = 'undefined'

    def __init__(self, ea):
        super(UndefinedEvent, self).__init__()
        self.ea = ea

    def __call__(self):
        idc.del_items(self.ea)
