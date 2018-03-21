# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import logging

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

from ..module import Module
from actions import OpenAction, SaveAction
from widgets import StatusWidget

logger = logging.getLogger('IDAConnect.Interface')


class Interface(Module):
    """
    The interface module, responsible for all interactions with the user.
    """

    @staticmethod
    def _findMainWindow():
        """
        Return the main window instance using Qt.

        :return: the main window
        """
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget
        import PyQt5
        PyQt5.QtWidgets.Menu
        QtWidget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)

        self._window = self._findMainWindow()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)

        self._labelWidget = None
        self._statusWidget = None

    def _install(self):
        self._installActions()
        self._installWidgets()
        return True

    def _uninstall(self):
        self._uninstallActions()
        self._uninstallWidgets()
        return True

    def _installActions(self):
        """
        Install the actions: install open and save.
        """
        self._openAction.install()
        self._saveAction.install()

    def _installWidgets(self):
        """
        Install the widgets: install label and status.
        """
        self._labelWidget = QLabel(self._plugin.description())
        self._window.statusBar().addPermanentWidget(self._labelWidget)

        self._statusWidget = StatusWidget(self._plugin)
        self._window.statusBar().addPermanentWidget(self._statusWidget)

        logger.debug("Installed widgets in status bar")

    def _uninstallActions(self):
        """
        Uninstall the actions: uninstall open and save.
        """
        self._openAction.uninstall()
        self._saveAction.uninstall()

    def _uninstallWidgets(self):
        """
        Uninstall the widgets: uninstall label and status.
        """
        self._window.statusBar().removeWidget(self._labelWidget)
        self._window.statusBar().removeWidget(self._statusWidget)

        logger.debug("Uninstalled widgets from status bar")

    def _updateActions(self):
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def notifyDisconnected(self):
        """
        Notify the user that a disconnection has occurred. This will mainly
        cause the status widget to update its display.
        """
        self._statusWidget.setState(StatusWidget.STATE_DISCONNECTED)
        self._statusWidget.setServer(StatusWidget.SERVER_DISCONNECTED)
        self._updateActions()

    def notifyConnecting(self):
        """
        Notify the user that a connection is being established. This will
        mainly cause the status widget to update its display.
        """
        self._statusWidget.setState(StatusWidget.STATE_CONNECTING)
        self._statusWidget.setServer(self._plugin.network.host)
        self._updateActions()

    def notifyConnected(self):
        """
        Notify the user that a connection has being established. This will
        mainly cause the status widget to update its display.
        """
        self._statusWidget.setState(StatusWidget.STATE_CONNECTED)
        self._updateActions()
