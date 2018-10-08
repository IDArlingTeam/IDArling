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
import time

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
        self._followed = None

        # Find the QMainWindow instance
        self._plugin.logger.debug("Searching for the main window")
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
        return self._widget

    @property
    def painter(self):
        return self._painter

    @property
    def invites(self):
        """Get all active invites."""
        invites = []
        for invite in self._invites:
            # Check if still active
            if (
                invite.callback
                and not invite.triggered
                and time.time() - invite.time < 180.0
            ):
                invites.append(invite)
        return invites

    @property
    def open_action(self):
        return self._open_action

    @property
    def save_action(self):
        return self._save_action

    @property
    def followed(self):
        return self._followed

    @followed.setter
    def followed(self, followed):
        self._followed = followed

    def _install(self):
        self._open_action.install()
        self._save_action.install()
        self._filter.install()
        self._widget.install(self._window)
        return True

    def _uninstall(self):
        self._open_action.uninstall()
        self._save_action.uninstall()
        self._filter.uninstall()
        self._widget.uninstall(self._window)
        return True

    def update(self):
        """Update the actions and widget."""
        if not self._plugin.network.connected:
            self.clear_invites()

        self._open_action.update()
        self._save_action.update()
        self._widget.refresh()

    def show_invite(self, text, icon, callback=None):
        """
        Display a toast notification to the user. The notification will have
        the specified text, icon and callback function (triggered on click).
        """
        # Check if notifications aren't disabled
        if not self._plugin.config["user"]["notifications"]:
            return

        invite = Invite(self._plugin, self._window)
        invite.time = time.time()
        invite.text = text
        invite.icon = QPixmap(icon)
        invite.callback = callback
        invite.show()
        self._invites.append(invite)

    def clear_invites(self):
        """Clears the invites list."""
        del self._invites[:]
        self._widget.refresh()
