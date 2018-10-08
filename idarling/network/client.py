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
import ida_auto
import ida_kernwin

from PyQt5.QtGui import QImage, QPixmap  # noqa: I202

from ..interface.widget import StatusWidget
from ..shared.commands import (
    DownloadFile,
    InviteToLocation,
    JoinSession,
    LeaveSession,
    UpdateLocation,
    UpdateUserColor,
    UpdateUserName,
)
from ..shared.packets import Command, Event
from ..shared.sockets import ClientSocket


class Client(ClientSocket):
    """
    This class represents a client socket for the client. It implements all the
    handlers for the packet the server is susceptible to send.
    """

    def __init__(self, plugin, parent=None):
        ClientSocket.__init__(self, plugin.logger, parent)
        self._plugin = plugin
        self._events = []

        # Setup command handlers
        self._handlers = {
            JoinSession: self._handle_join_session,
            LeaveSession: self._handle_leave_session,
            UpdateLocation: self._handle_update_location,
            InviteToLocation: self._handle_invite_to_location,
            UpdateUserName: self._handle_update_user_name,
            UpdateUserColor: self._handle_update_user_color,
            DownloadFile.Query: self._handle_download_file,
        }

    def call_events(self):
        while self._events and ida_auto.get_auto_state() == ida_auto.AU_NONE:
            packet = self._events.pop(0)
            self._call_event(packet)

    def _call_event(self, packet):
        self._plugin.core.unhook_all()

        try:
            packet()
        except Exception as e:
            self._logger.warning("Error while calling event")
            self._logger.exception(e)

        self._plugin.core.hook_all()

        # Check for de-synchronization
        if self._plugin.core.tick >= packet.tick:
            self._logger.warning("De-synchronization detected!")
            packet.tick = self._plugin.core.tick
        self._plugin.core.tick = packet.tick
        self._plugin.logger.debug("returning from call_event")

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # If we already have some events queued
            if self._events or ida_auto.get_auto_state() != ida_auto.AU_NONE:
                self._events.append(packet)
            else:
                self._call_event(packet)

        else:
            return False
        return True

    def send_packet(self, packet):
        if isinstance(packet, Event):
            self._plugin.core.tick += 1
            packet.tick = self._plugin.core.tick
        return ClientSocket.send_packet(self, packet)

    def disconnect(self, err=None):
        ret = ClientSocket.disconnect(self, err)
        self._plugin.network._client = None
        self._plugin.network._server = None

        # Update the user interface
        self._plugin.interface.update()
        self._plugin.interface.clear_invites()
        return ret

    def _check_socket(self):
        was_connected = self._connected
        ret = ClientSocket._check_socket(self)
        if not was_connected and self._connected:
            # Update the user interface
            self._plugin.interface.update()
            # Subscribe to the events
            self._plugin.core.join_session()
        return ret

    def _handle_join_session(self, packet):
        # Update the users list
        user = {"color": packet.color, "ea": packet.ea}
        self._plugin.core.add_user(packet.name, user)

        # Show a toast notification
        if packet.silent:
            return
        text = "%s joined the session" % packet.name
        template = QImage(self._plugin.plugin_resource("user.png"))
        icon = StatusWidget.make_icon(template, packet.color)
        self._plugin.interface.show_invite(text, icon)

    def _handle_leave_session(self, packet):
        # Update the users list
        user = self._plugin.core.remove_user(packet.name)
        # Refresh the users count
        self._plugin.interface.widget.refresh()

        # Show a toast notification
        if packet.silent:
            return
        text = "%s left the session" % packet.name
        template = QImage(self._plugin.plugin_resource("user.png"))
        icon = StatusWidget.make_icon(template, user["color"])
        self._plugin.interface.show_invite(text, icon)

    def _handle_invite_to_location(self, packet):
        # Show a toast notification
        text = "%s - Jump to %#x" % (packet.name, packet.loc)
        icon = self._plugin.plugin_resource("location.png")

        def callback():
            ida_kernwin.jumpto(packet.loc)

        self._plugin.interface.show_invite(text, QPixmap(icon), callback)

    def _handle_update_user_name(self, packet):
        # Update the users list
        user = self._plugin.core.remove_user(packet.old_name)
        self._plugin.core.add_user(packet.new_name, user)

    def _handle_update_user_color(self, packet):
        # Update the users list
        user = self._plugin.core.get_user(packet.name)
        user["color"] = packet.new_color
        self._plugin.core.add_user(packet.name, user)

    def _handle_update_location(self, packet):
        # Update the users list
        user = self._plugin.core.get_user(packet.name)
        user["ea"] = packet.ea
        self._plugin.core.add_user(packet.name, user)

        followed = self._plugin.interface.followed
        if followed == packet.name or followed == "everyone":
            ida_kernwin.jumpto(packet.ea)

    def _handle_download_file(self, query):
        # Upload the current database
        self._plugin.interface.save_action.handler.upload_file(
            self._plugin, DownloadFile.Reply(query)
        )
