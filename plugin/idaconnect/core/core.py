import json
import logging
import os

import ida_idp
import ida_kernwin
import idaapi

from ..module import Module
from ..utilities.misc import localResource
from ..shared.commands import Subscribe, Unsubscribe
from hooks import Hooks, IDBHooks, IDPHooks, HexRaysHooks

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
        self._hxeHooks = None

        self._uiHooksCore = None
        self._idbHooksCore = None

        self._repo = None
        self._branch = None

    def _install(self):
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self._hxeHooks = HexRaysHooks(self._plugin)

        class UIHooksCore(Hooks, ida_kernwin.UI_Hooks):
            """
            The concrete class for UI-related events.
            """

            def __init__(self, plugin):
                ida_kernwin.UI_Hooks.__init__(self)
                Hooks.__init__(self, plugin)

            def ready_to_run(self, *_):
                self._plugin.core.loadNetnode()
                # Subscribe to the events stream if needed
                if self._plugin.core.repo and self._plugin.core.branch:
                    self._plugin.network.sendPacket(Subscribe(
                        self._plugin.core.repo, self._plugin.core.branch))
                    self._plugin.core.hookAll()
        self._uiHooksCore = UIHooksCore(self._plugin)
        self._uiHooksCore.hook()

        class IDBHooksCore(Hooks, ida_idp.IDB_Hooks):
            """
            The concrete class for all IDB-related events.
            """

            def __init__(self, plugin):
                ida_idp.IDB_Hooks.__init__(self)
                Hooks.__init__(self, plugin)

            def closebase(self):
                self._plugin.network.sendPacket(Unsubscribe())
                self._plugin.core.unhookAll()
                return 0
        self._idbHooksCore = IDBHooksCore(self._plugin)
        self._idbHooksCore.hook()

        logger.debug("Installing hooks")
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
        self._hxeHooks.hook()

    def unhookAll(self):
        """
        Remove the hooks to not be notified of incoming IDA events.
        """
        self._idbHooks.unhook()
        self._idpHooks.unhook()
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

    def loadState(self):
        """
        Load the state file if it exists.
        """
        statePath = localResource('files', 'state.json')
        if os.path.isfile(statePath):
            with open(statePath, 'rb') as stateFile:
                state = json.loads(stateFile.read())
                logger.debug("Loaded state: %s" % state)
                if state['connected']:
                    self._plugin.network.connect(state['host'], state['port'])
                if 'cleanup' in state and state['cleanup']:
                    # Remove unpacked files from parent instance
                    idbFile, idbExt = os.path.splitext(state['cleanup'])
                    for extension in ['.id0', '.id1', '.nam', '.seg', '.til']:
                        if os.path.exists(idbFile + extension):
                            os.remove(idbFile + extension)
            os.remove(statePath)

    def saveState(self, cleanup=None):
        """
        Save the state file.

        :param cleanup: the path of the file to cleanup
        """
        statePath = localResource('files', 'state.json')
        with open(statePath, 'wb') as stateFile:
            state = {
                'connected': self._plugin.network.connected,
                'host': self._plugin.network.host,
                'port': self._plugin.network.port,
            }
            if cleanup:
                state['cleanup'] = cleanup
            logger.debug("Saved state: %s" % state)
            stateFile.write(json.dumps(state))

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

    def notifyConnected(self):
        """
        If the core has loaded a database, subscribe to the events stream.
        """
        if self._repo and self._branch:
            self._plugin.network.sendPacket(
                Subscribe(self._repo, self._branch))
            self.hookAll()
