import logging

from hooks import IDBHooks, IDPHooks
from ..module import Module

logger = logging.getLogger('IDAConnect.Core')


class Core(Module):
    """
    The core module, responsible for all interactions with the IDA kernel.
    """

    def __init__(self, plugin):
        """
        Instantiate the core module.

        :param IDAConnect plugin: the plugin instance
        """
        super(Core, self).__init__(plugin)

        self._idbHooks = None
        self._idpHooks = None

    def _install(self):
        """
        Install the core module: add the hooks.

        :rtype: bool
        """
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)

        logger.debug("Installing hooks")
        self.hookAll()
        return True

    def _uninstall(self):
        """
        Uninstall the core module: remove the hooks.

        :rtype: bool
        """
        logger.debug("Uninstalling hooks")
        self.unhookAll()
        return True

    def hookAll(self):
        """
        Add the hooks to be notified of incoming IDA events.
        """
        self._idbHooks.hook()
        self._idpHooks.hook()

    def unhookAll(self):
        """
        Remove the hooks to not be notified of incoming IDA events.
        """
        self._idbHooks.unhook()
        self._idpHooks.unhook()
