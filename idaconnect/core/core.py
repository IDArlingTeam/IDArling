# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import collections
import json
import logging
import os

import ida_idp
import ida_kernwin
import idaapi

from ..module import Module
from ..utilities.misc import local_resource
from ..shared.commands import Subscribe, Unsubscribe
from .hooks import Hooks, IDBHooks, IDPHooks, HexRaysHooks

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
        self._tick = 0
        self._servers = []

    def _install(self):
        self._idbHooks = IDBHooks(self._plugin)
        self._idpHooks = IDPHooks(self._plugin)
        self._hxeHooks = HexRaysHooks(self._plugin)

        core = self

        class UIHooksCore(Hooks, ida_kernwin.UI_Hooks):
            """
            The concrete class for all core UI-related events.
            """

            def __init__(self, plugin):
                ida_kernwin.UI_Hooks.__init__(self)
                Hooks.__init__(self, plugin)

            def ready_to_run(self, *_):
                core.load_netnode()

                # Subscribe to the events stream if needed
                if core.repo and core.branch:
                    self._plugin.network.send_packet(Subscribe(
                        core.repo, core.branch, core.tick))
                    core.hook_all()

        self._uiHooksCore = UIHooksCore(self._plugin)
        self._uiHooksCore.hook()

        class IDBHooksCore(Hooks, ida_idp.IDB_Hooks):
            """
            The concrete class for all core IDB-related events.
            """

            def __init__(self, plugin):
                ida_idp.IDB_Hooks.__init__(self)
                Hooks.__init__(self, plugin)

            def closebase(self):
                self._plugin.network.send_packet(Unsubscribe())
                core.unhook_all()
                core.repo = None
                core.branch = None
                return 0

        self._idbHooksCore = IDBHooksCore(self._plugin)
        self._idbHooksCore.hook()

        logger.debug("Installing hooks")
        return True

    def _uninstall(self):
        logger.debug("Uninstalling hooks")
        self._idbHooksCore.unhook()
        self._uiHooksCore.unhook()
        self.unhook_all()
        return True

    def hook_all(self):
        """
        Add the hooks to be notified of incoming IDA events.
        """
        self._idbHooks.hook()
        self._idpHooks.hook()
        self._hxeHooks.hook()

    def unhook_all(self):
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

    @property
    def tick(self):
        """
        Get the current tick.

        :return: the tick
        """
        return self._tick

    @tick.setter
    def tick(self, tick):
        """
        Set the current tick.

        :param tick: the tick
        """
        self._tick = tick

    @property
    def servers(self):
        """
        Get the list of servers.

        :return: the servers
        """
        return self._servers

    @servers.setter
    def servers(self, servers):
        """
        Set the list of servers.

        :param servers: the list of server
        """
        self._servers = servers

    def load_state(self):
        """
        Load the state file if it exists.
        """
        statePath = local_resource('files', 'state.json')
        if os.path.isfile(statePath):
            with open(statePath, 'rb') as stateFile:
                state = json.loads(stateFile.read())
                logger.debug("Loaded state: %s" % state)

                # Load the server list from state
                Server = collections.namedtuple('Server', ['host', 'port'])
                self._servers = [Server(*s) for s in state['servers']]

                # Remove unpacked files from parent instance
                if 'cleanup' in state and state['cleanup']:
                    idbFile, idbExt = os.path.splitext(state['cleanup'])
                    for extension in ['.id0', '.id1', '.nam', '.seg', '.til']:
                        if os.path.exists(idbFile + extension):
                            os.remove(idbFile + extension)

                # Reconnect to the same server as parent instance
                if state['connected']:
                    self._plugin.network.connect(state['host'], state['port'])

    def save_state(self, cleanup=None):
        """
        Save the state file.

        :param cleanup: the path of the file to cleanup
        """
        statePath = local_resource('files', 'state.json')
        with open(statePath, 'wb') as stateFile:
            state = {
                'connected': self._plugin.network.connected,
                'host': self._plugin.network.host,
                'port': self._plugin.network.port,
                'servers': [[s.host, s.port] for s in self._servers],
            }

            # Remember to cleanup the temp files
            if cleanup:
                state['cleanup'] = cleanup

            logger.debug("Saved state: %s" % state)
            stateFile.write(json.dumps(state))

    def load_netnode(self):
        """
        Load the netnode from the IDA database.
        """
        node = idaapi.netnode()
        if node.create(Core.NETNODE_NAME):
            return  # node doesn't exists

        self._repo = node.hashval('hash')
        self._branch = node.hashval('uuid')
        self._tick = node.hashval('tick')
        self._tick = int(self._tick) if self._tick else 0

        logger.debug("Loaded netnode: repo=%s, branch=%s, tick=%d"
                     % (self._repo, self._branch, self._tick))

    def save_netnode(self):
        """
        Save the netnode in the IDA database.
        """
        node = idaapi.netnode()
        if not node.create(Core.NETNODE_NAME):
            pass  # node already exists

        node.hashset('hash', self._repo)
        node.hashset('uuid', self._branch)
        node.hashset('tick', str(self._tick))

        logger.debug("Saved netnode: repo=%s, branch=%s, tick=%d"
                     % (self._repo, self._branch, self._tick))

    def notify_connected(self):
        if self._repo and self._branch:
            self._plugin.network.send_packet(
                Subscribe(self._repo, self._branch, self._tick))
            self.hook_all()
