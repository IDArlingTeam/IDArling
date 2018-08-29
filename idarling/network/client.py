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

import ida_kernwin

from ..shared.commands import (Subscribe, Unsubscribe, InviteTo,
                               UpdateCursors, UserRenamed, UserColorChanged)
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
            Subscribe: self._handle_subscribe,
            Unsubscribe: self._handle_unsubscribe,
            InviteTo: self._handle_invite_to,
            UserRenamed: self._handle_user_renamed,
            UserColorChanged: self._handle_user_color_changed
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

    def _handle_subscribe(self, packet):
        self._plugin.interface.painter.paint(packet.name,
                                             packet.color,
                                             packet.ea)

    def _handle_unsubscribe(self, packet):
        self._plugin.interface.painter.unpaint(packet.name)

    def _handle_invite_to(self, packet):
        text = "%s - Jump to %#x" % (packet.name, packet.loc)
        icon = self._plugin.resource('location.png')

        def callback():
            ida_kernwin.jumpto(packet.loc)
        self._plugin.interface.show_notification(text, icon, callback)

    def _handle_update_cursors(self, packet):
        self._plugin.interface.painter.paint(packet.name,
                                             packet.color,
                                             packet.ea)

    def _handle_user_renamed(self, packet):
        self._plugin.interface.painter.rename_user(packet.old_name,
                                                   packet.new_name)

    def _handle_user_color_changed(self, packet):
        self._plugin.interface.painter.change_user_color(packet.name,
                                                         packet.old_color,
                                                         packet.new_color)

    @property
    def users(self):
        return self._users
