import logging

import idc
import ida_idp

from events import *


logger = logging.getLogger('IDAConnect.Core')

# -----------------------------------------------------------------------------
# Hooks
# -----------------------------------------------------------------------------


class Hooks(object):

    def __init__(self, plugin):
        self._network = plugin.getNetwork()

    def _sendEvent(self, event):
        # Forward packet to network
        self._network.sendPacket(event)

# -----------------------------------------------------------------------------
# IDB Hooks
# -----------------------------------------------------------------------------


class IDBHooks(Hooks, ida_idp.IDB_Hooks):

    def __init__(self, plugin):
        ida_idp.IDB_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def make_code(self, insn):
        self._sendEvent(MakeCodeEvent(insn.ea))
        return 0

    def make_data(self, ea, flags, tid, size):
        self._sendEvent(MakeDataEvent(ea, flags, size, tid))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._sendEvent(RenamedEvent(ea, new_name, local_name))
        return 0

    def func_added(self, func):
        self._sendEvent(FuncAddedEvent(func.startEA, func.endEA))
        return 0

    def deleting_func(self, func):
        self._sendEvent(DeletingFuncEvent(func.startEA))
        return 0

    def set_func_start(self, func, new_start):
        self._sendEvent(SetFuncStartEvent(func.startEA, new_start))
        return 0

    def set_func_end(self, func, new_end):
        self._sendEvent(SetFuncEndEvent(func.startEA, new_end))
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = idc.get_cmt(ea, repeatable_cmt)
        cmt = '' if not cmt else cmt
        self._sendEvent(CmtChangedEvent(ea, cmt, repeatable_cmt))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._sendEvent(ExtraCmtChangedEvent(ea, line_idx, cmt))
        return 0

    def ti_changed(self, ea, type_, fname):
        py_type = idc.GetTinfo(ea)
        self._sendEvent(TiChangedEvent(ea, py_type))
        return 0

    def op_type_changed(self, ea, n):
        def gather_enum_info(ea, n):
            id = idaapi.get_enum_id(ea, n)[0]
            serial = idaapi.get_enum_idx(id)
            return id, serial

        extra = {}
        flags = idc.get_full_flags(ea)
        if n == 0:
            if idc.isHex0(flags):
                op = 'hex'
            elif idc.isBin0(flags):
                op = 'bin'
            elif idc.isDec0(flags):
                op = 'dec'
            elif idc.isChar0(flags):
                op = 'chr'
            elif idc.isOct0(flags):
                op = 'oct'
            elif idc.isEnum0(flags):
                op = 'enum'
                id, serial = gather_enum_info(ea, n)
                extra['id'] = id
                extra['serial'] = serial
            else:
                # FIXME: Find a better way
                return 0
        else:
            if idc.isHex1(flags):
                op = 'hex'
            elif idc.isBin1(flags):
                op = 'bin'
            elif idc.isDec1(flags):
                op = 'dec'
            elif idc.isChar1(flags):
                op = 'chr'
            elif idc.isOct1(flags):
                op = 'oct'
            elif idc.isEnum1(flags):
                op = 'enum'
                id, serial = gather_enum_info(ea, n)
                extra['id'] = id
                extra['serial'] = serial
            else:
                # FIXME: Find a better way
                return 0
        self._sendEvent(OpTypeChangedEvent(ea, n, op, extra))
        return 0

    def enum_created(self, enum):
        name = idc.get_enum_name(enum)
        self._sendEvent(EnumCreatedEvent(enum, name))
        return 0

    def enum_deleted(self, enum):
        self._sendEvent(EnumDeletedEvent(enum))
        return 0

    def enum_renamed(self, tid):
        new_name = idaapi.get_enum_name(tid)
        self._sendEvent(EnumRenamedEvent(tid, new_name))
        return 0

    def enum_bf_changed(self, tid):
        bf_flag = 1 if idc.IsBitfield(tid) else 0
        self._sendEvent(EnumBfChangedEvent(tid, bf_flag))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = idaapi.get_enum_cmt(tid, repeatable_cmt)
        self._sendEvent(EnumCmtChangedEvent(tid, cmt, repeatable_cmt))
        return 0

    def enum_member_created(self, id, cid):
        name = idaapi.get_enum_member_name(cid)
        value = idaapi.get_enum_member_value(cid)
        bmask = idaapi.get_enum_member_bmask(cid)
        self._sendEvent(EnumMemberCreatedEvent(id, name, value, bmask))
        return 0

    def enum_member_deleted(self, id, cid):
        value = idaapi.get_enum_member_value(cid)
        serial = idaapi.get_enum_member_serial(cid)
        bmask = idaapi.get_enum_member_bmask(cid)
        self._sendEvent(EnumMemberDeletedEvent(id, value, serial, bmask))
        return 0

    def struc_created(self, tid):
        name = idaapi.get_struc_name(tid)
        self._sendEvent(StrucCreatedEvent(tid, name))
        return 0

    def struc_deleted(self, tid):
        self._sendEvent(StrucDeletedEvent(tid))
        return 0

    def struc_renamed(self, sptr):
        new_name = idaapi.get_struc_name(sptr.id)
        self._sendEvent(StrucRenamedEvent(sptr.id, new_name))
        return 0

    def struc_cmt_changed(self, tid, repeatable_cmt):
        cmt = idaapi.get_struc_cmt(tid, repeatable_cmt)
        self._sendEvent(StrucCmtChangedEvent(tid, cmt, repeatable_cmt))
        return 0

# -----------------------------------------------------------------------------
# IDP Hooks
# -----------------------------------------------------------------------------


class IDPHooks(Hooks, ida_idp.IDP_Hooks):

    def __init__(self, plugin):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def ev_undefine(self, ea):
        self._sendEvent(UndefinedEvent(ea))
        return 0
