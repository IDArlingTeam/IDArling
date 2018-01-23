import logging

from ..module import Module
from hooks import IDBHooks, IDPHooks


logger = logging.getLogger('IDAConnect.Core')

# -----------------------------------------------------------------------------
# Core Module
# -----------------------------------------------------------------------------


class Core(Module):

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)

        self._idbHooks = None
        self._idpHooks = None

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def _install(self):
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)

        logger.debug("Installing hooks")
        self.hookAll()

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self.unhookAll()

    # -------------------------------------------------------------------------
    # Hooks
    # -------------------------------------------------------------------------

    def hookAll(self):
        self._idbHooks.hook()
        self._idpHooks.hook()

    def unhookAll(self):
        self._idbHooks.unhook()
        self._idpHooks.unhook()
