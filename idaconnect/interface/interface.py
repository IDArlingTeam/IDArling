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

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

from ..module import Module
from .actions import OpenAction, SaveAction
from .widgets import StatusWidget

logger = logging.getLogger('IDAConnect.Interface')


class Interface(Module):
    """
    The interface module, responsible for all interactions with the user.
    """

    @staticmethod
    def _find_main_window():
        """
        Return the main window instance using Qt.

        :return: the main window
        """
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._window = self._find_main_window()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)
        self._statusWidget = None

    def _install(self):
        self._openAction.install()
        self._saveAction.install()

        self._statusWidget = StatusWidget(self._plugin)
        self._window.statusBar().addPermanentWidget(self._statusWidget)
        logger.debug("Installed widgets in status bar")
        return True

    def _uninstall(self):
        self._openAction.uninstall()
        self._saveAction.uninstall()

        self._window.statusBar().removeWidget(self._statusWidget)
        logger.debug("Uninstalled widgets from status bar")
        return True

    def _update_actions(self):
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def notify_disconnected(self):
        self._statusWidget.set_state(StatusWidget.STATE_DISCONNECTED)
        self._statusWidget.set_server(StatusWidget.SERVER_DISCONNECTED)
        self._update_actions()

    def notify_connecting(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTING)
        self._statusWidget.set_server(self._plugin.network.host)
        self._update_actions()

    def notify_connected(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTED)
        self._update_actions()
