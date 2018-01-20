import logging

import ida_idp
import idc

from events.events import Event
from events.events_idp import *
from events.events_idb import *

logger = logging.getLogger("IDAConnect.Hooks")


class HooksBase(object):

    def __init__(self, network):
        self._network = network

    def _send_event(self, event):
        self._network.send_event(event)


class IDPHooks(ida_idp.IDP_Hooks, HooksBase):

    def __init__(self, network):
        ida_idp.IDP_Hooks.__init__(self)
        HooksBase.__init__(self, network)

    def ev_undefine(self, ea):
        self._send_event(UndefinedEvent(ea))
        return 0


class IDBHooks(ida_idp.IDB_Hooks, HooksBase):

    def __init__(self, network):
        ida_idp.IDB_Hooks.__init__(self)
        HooksBase.__init__(self, network)

    def make_code(self, insn):
        self._send_event(MakeCodeEvent(insn.ea))
        return 0

    def make_data(self, ea, flags, tid, size):
        self._send_event(MakeDataEvent(ea, flags, tid, size))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._send_event(RenamedEvent(ea, new_name, local_name))
        return 0

    def func_added(self, func):
        self._send_event(FuncAddedEvent(func.startEA, func.endEA))
        return 0

    def deleting_func(self, func):
        self._send_event(DeletingFuncEvent(func.startEA))
        return 0

    def set_func_start(self, func, new_ea):
        self._send_event(SetFuncStartEvent(func.startEA, new_ea))
        return 0

    def set_func_end(self, func, new_ea):
        self._send_event(SetFuncEndEvent(func.startEA, new_ea))
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = idc.get_cmt(ea, repeatable_cmt)
        if not cmt:
            cmt = ""
        self._send_event(CmtChangedEvent(ea, repeatable_cmt, cmt))
        return 0


class Hooks(object):

    def __init__(self, plugin):
        super(Hooks, self).__init__()
        self._plugin = plugin
        self._installed = False

    def install(self):
        if self._installed:
            return
        logger.debug("Installing hooks")
        self._idp_hooks = IDPHooks(self._plugin.network)
        self._idb_hooks = IDBHooks(self._plugin.network)
        self.hook_all()
        self._installed = True

    def uninstall(self):
        if not self._installed:
            return
        logger.debug("Uninstalling hooks")
        self.unhook_all()
        self._installed = False

    def hook_all(self):
        self._idp_hooks.hook()
        self._idb_hooks.hook()

    def unhook_all(self):
        self._idp_hooks.unhook()
        self._idb_hooks.unhook()
