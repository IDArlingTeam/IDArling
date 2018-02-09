import logging

import idaapi

from ..module import Module
from hooks import IDBHooks, IDPHooks, UIHooks, HexRaysHooks

logger = logging.getLogger('IDAConnect.Core')


class Core(Module):
    """
    The core module, responsible for all interactions with the IDA kernel.
    """
    NETNODE_NAME = '$ idaconnect'

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)

        self._idbHooks = None
        self._idpHooks = None
        self._uiHooks = None
        self._hxeHooks = None

        self._repo = None
        self._branch = None

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

    @property
    def repo(self):
        """
        Get the current repository hash.

        :return: the hash
        """
        return self._repo

    @repo.setter
    def repo(self, hash):
        """
        Set the current repository hash.

        :param hash: the hash
        """
        self._repo = hash

    @property
    def branch(self):
        """
        Get the current branch UUID.

        :return: the UUID
        """
        return self._branch

    @branch.setter
    def branch(self, uuid):
        """
        Set the current branch UUID.

        :param uuid: the UUID
        """
        self._branch = uuid

    def loadNetnode(self):
        """
        Load the netnode if it exists.
        """
        node = idaapi.netnode()
        if node.create(Core.NETNODE_NAME):
            return  # node doesn't exists
        self._repo = node.hashval('hash')
        self._branch = node.hashval('uuid')
        logger.debug("Loaded netnode: %s, %s" % (self._repo, self._branch))

    def saveNetnode(self):
        """
        Save the netnode.
        """
        node = idaapi.netnode()
        if not node.create(Core.NETNODE_NAME):
            pass  # node already exists
        node.hashset('hash', self._repo)
        node.hashset('uuid', self._branch)
        logger.debug("Saved netnode: %s, %s" % (self._repo, self._branch))
