import logging

import ida_idp

# Import ABC and events
from hooks_abc import Hooks
from ..events.events_idp import *


logger = logging.getLogger('IDAConnect.Core')

# -----------------------------------------------------------------------------
# IDP Hooks
# -----------------------------------------------------------------------------


class IDPHooks(ida_idp.IDP_Hooks, Hooks):

    def __init__(self, plugin):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def ev_undefine(self, ea):
        self._sendEvent(UndefinedEvent(ea))
        return 0
