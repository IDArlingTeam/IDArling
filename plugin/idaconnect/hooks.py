import logging

from core import Core

from hook.hooks_idb import IDBHooks
from hook.hooks_idp import IDPHooks


logger = logging.getLogger("IDAConnect.Hooks")


class HooksCore(Core):

    def _install(self):
        logger.debug("Installing hooks")
        self._idpHooks = IDPHooks(self._plugin.network)
        self._idbHooks = IDBHooks(self._plugin.network)
        self.hookAll()

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self.unhookAll()

    def hookAll(self):
        self._idpHooks.hook()
        self._idbHooks.hook()

    def unhookAll(self):
        self._idpHooks.unhook()
        self._idbHooks.unhook()
