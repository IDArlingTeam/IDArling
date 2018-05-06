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
import logging

import ida_funcs

from ..shared.commands import UpdateCursors, RemoveCursor
from ..shared.packets import Command, Event
from ..shared.sockets import ClientSocket

logger = logging.getLogger('IDArling.Network')


class Client(ClientSocket):
    """
    The client (client-side) implementation.
    """

    def __init__(self, plugin, parent=None):
        """
        Initializes the client.

        :param plugin: the plugin instance
        """
        ClientSocket.__init__(self, logger, parent)
        self._plugin = plugin
        self._users = {}
        self._handlers = {
            UpdateCursors: self._handle_update_cursors,
            RemoveCursor: self._handle_remove_cursor,
        }

    def disconnect(self, err=None):
        ClientSocket.disconnect(self, err)
        logger.info("Connection lost")

        # Notify the plugin
        self._plugin.notify_disconnected()

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # Call the event
            self._plugin.core.unhook_all()
            try:
                packet()
            except Exception as e:
                self._logger.warning("Error while calling event")
                self._logger.exception(e)
            if self._plugin.core.tick >= packet.tick:
                self._logger.warning("De-synchronization detected!")
                packet.tick = self._plugin.core.tick
            self._plugin.core.tick = packet.tick
            self._plugin.core.hook_all()
        else:
            return False
        return True

    def send_packet(self, packet):
        if isinstance(packet, Event):
            self._plugin.core.tick += 1
            packet.tick = self._plugin.core.tick
        return ClientSocket.send_packet(self, packet)

    def _handle_update_cursors(self, packet):
        prev_ea = self._users.get(packet.color)
        self._users[packet.color] = packet.ea
        cur_func = ida_funcs.get_func(packet.ea)
        if prev_ea:
            # Hack, two packets are received...
            # TODO find why and remove this hack
            if prev_ea == packet.ea:
                return
            prev_func = ida_funcs.get_func(prev_ea)
        else:
            prev_func = None

        self._plugin.interface.color_navbar(self._users)
        self._plugin.interface.color_current_func(cur_func, prev_func,
                                                  packet.color)
        self._plugin.interface.color_func_insts(packet.ea)
        self._plugin.interface.color_current_inst(packet.ea, packet.color)
        if prev_ea:
            self._plugin.interface.clear_prev_inst(packet.ea, prev_ea)
            self._plugin.interface.clear_prev_func_insts(prev_ea)
            self._plugin.interface.clear_prev_func(packet.ea, cur_func,
                                                   prev_func)

    def _handle_remove_cursor(self, packet):
        ea = self._users.pop(packet.color)
        self._plugin.interface.color_navbar(self._users)
        self._plugin.interface.clear_current_inst(ea)
        self._plugin.interface.clear_current_func(ea)

    @property
    def users(self):
        return self._users
