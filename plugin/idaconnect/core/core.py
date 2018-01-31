import logging

from ..module import Module
from hooks import IDBHooks, IDPHooks, HexRaysHooks


logger = logging.getLogger('IDAConnect.Core')


class Core(Module):
    """
    The core module, responsible for all interactions with the IDA kernel.
    """

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)

        self._idbHooks = None
        self._idpHooks = None
        self._hexraysHooks = None

    def _install(self):
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self._hexraysHooks = HexRaysHooks(self._plugin)

        logger.debug("Installing hooks")
        self.hookAll()
        return True

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self.unhookAll()
        del self._hexraysHooks
        return True

    def hookAll(self):
        """
        Add the hooks to be notified of incoming IDA events.
        """
        self._idbHooks.hook()
        self._idpHooks.hook()
        self._hexraysHooks.hook()

    def unhookAll(self):
        """
        Remove the hooks to not be notified of incoming IDA events.
        """
        self._idbHooks.unhook()
        self._idpHooks.unhook()
        self._hexraysHooks.unhook()
