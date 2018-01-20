import ida_idp

from hooks_abc import Hooks
from ..event.events_idp import *
from ..event.events_idb import *


class IDPHooks(ida_idp.IDP_Hooks, Hooks):

    def __init__(self, network):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, network)

    def ev_undefine(self, ea):
        self._sendEvent(UndefinedEvent(ea))
        return 0
