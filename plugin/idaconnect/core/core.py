import logging

from ..module import Module

# Import hooks
from hooks_idb import IDBHooks
from hooks_idp import IDPHooks


logger = logging.getLogger('IDAConnect.Core')

# -----------------------------------------------------------------------------
# Core Module
# -----------------------------------------------------------------------------


class Core(Module):

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)

        # Variable initialization
        self._idbHooks = None
        self._idpHooks = None

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def _install(self):
        logger.debug("Installing hooks")
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self.hookAll()

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self.unhookAll()

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def hookAll(self):
        self._idbHooks.hook()
        self._idpHooks.hook()

    def unhookAll(self):
        self._idbHooks.unhook()
        self._idpHooks.unhook()
