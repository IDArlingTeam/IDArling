import logging

from ..module import Module
from .hooks import IDBHooks, IDPHooks, HexRaysHooks


MYPY = False
if MYPY:
    from typing import Optional
    from ..plugin import IDAConnect


logger = logging.getLogger('IDAConnect.Core')


class Core(Module):
    """
    The core module, responsible for all interactions with the IDA kernel.
    """

    def __init__(self, plugin):
        # type: (IDAConnect) -> None
        super(Core, self).__init__(plugin)

        self._idbHooks = None  # type: Optional[IDBHooks]
        self._idpHooks = None  # type: Optional[IDPHooks]
        self._hexraysHooks = None  # type: Optional[HexRaysHooks]

    def _install(self):
        # type: () -> bool
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self._hexraysHooks = HexRaysHooks(self._plugin)

        logger.debug("Installing hooks")
        self.hookAll()
        return True

    def _uninstall(self):
        # type: () -> bool
        logger.debug("Uninstalling hooks")
        self.unhookAll()
        return True

    def hookAll(self):
        # type: () -> None
        """
        Add the hooks to be notified of incoming IDA events.
        """
        if self._idbHooks:
            self._idbHooks.hook()
        if self._idpHooks:
            self._idpHooks.hook()
        if self._hexraysHooks:
            self._hexraysHooks.hook()

    def unhookAll(self):
        # type: () -> None
        """
        Remove the hooks to not be notified of incoming IDA events.
        """
        if self._idbHooks:
            self._idbHooks.unhook()
        if self._idpHooks:
            self._idpHooks.unhook()
        if self._hexraysHooks:
            self._hexraysHooks.unhook()
