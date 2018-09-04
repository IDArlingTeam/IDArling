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
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import qApp, QMainWindow

from .actions import OpenAction, SaveAction
from .filter import EventFilter
from .invites import Invite
from .painter import Painter
from .widget import StatusWidget
from ..module import Module


class Interface(Module):
    """
    This is the interface module. It is responsible for all interactions with
    the user interface. It manages the all the actions, dialog, cursors,
    invites and the handy status bar widget.
    """

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._invites = []

        # Find the QMainWindow instance
        for widget in qApp.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                self._window = widget
                break

        self._open_action = OpenAction(plugin)
        self._save_action = SaveAction(plugin)

        self._painter = Painter(plugin)
        self._filter = EventFilter(plugin)
        self._widget = StatusWidget(plugin)

    @property
    def widget(self):
        """Get the status widget."""
        return self._widget

    @property
    def painter(self):
        """Get the painter instance."""
        return self._painter

    @property
    def invites(self):
        """Get active invites."""
        return self._invites

    def _install(self):
        self._open_action.install()
        self._save_action.install()
        self._painter.install()
        self._filter.install()
        self._widget.install(self._window)
        self._plugin.logger.debug("Installed user interface elements")
        return True

    def _uninstall(self):
        self._painter.uninstall()
        self._open_action.uninstall()
        self._save_action.uninstall()
        self._filter.uninstall()
        self._widget.uninstall(self._window)
        self._plugin.logger.debug("Uninstalled user interface elements")
        return True

    def _update_actions(self):
        """Update the actions status (enabled or not)."""
        self._open_action.update()
        self._save_action.update()

    def show_invite(self, text, icon, callback):
        """
        Display a toast notification to the user. The notification will have
        the specified text, icon and callback function (triggered on click).
        """
        if not self._plugin.config["user"]["notifications"]:
            return
        invite = Invite(self._plugin, self._window)
        invite.text = text
        invite.icon = QPixmap(icon)
        invite.callback = callback
        invite.show()
        self._invites.append(invite)

    def notify_disconnected(self):
        # Update the widget's state
        del self._invites[:]
        self._widget.set_state(StatusWidget.STATE_DISCONNECTED)
        self._widget.set_server(None)
        self._update_actions()

    def notify_connecting(self):
        # Update the widget's state
        self._widget.set_state(StatusWidget.STATE_CONNECTING)
        self._widget.set_server(self._plugin.network.server)
        self._update_actions()

    def notify_connected(self):
        # Update the widget's state
        self._widget.set_state(StatusWidget.STATE_CONNECTED)
        self._widget.set_server(self._plugin.network.server)
        self._update_actions()
