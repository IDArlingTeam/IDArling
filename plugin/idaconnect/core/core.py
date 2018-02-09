import logging

from ..module import Module
from hooks import IDBHooks, IDPHooks, UIHooks, HexRaysHooks

logger = logging.getLogger('IDAConnect.Core')


class Core(Module):
    """
    The core module, responsible for all interactions with the IDA kernel.
    """

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)

        self._idbHooks = None
        self._idpHooks = None
        self._uiHooks = None
        self._hxeHooks = None

    def _install(self):
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self._uiHooks = UIHooks(self._plugin)
        self._hxeHooks = HexRaysHooks(self._plugin)

        logger.debug("Installing hooks")
        self.hookAll()
        return True

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self.unhookAll()
        return True

    def hookAll(self):
        """
        Add the hooks to be notified of incoming IDA events.
        """
        self._idbHooks.hook()
        self._idpHooks.hook()
        self._uiHooks.hook()
        self._hxeHooks.hook()

    def unhookAll(self):
        """
        Remove the hooks to not be notified of incoming IDA events.
        """
        self._idbHooks.unhook()
        self._idpHooks.unhook()
        self._uiHooks.unhook()
        self._hxeHooks.unhook()
