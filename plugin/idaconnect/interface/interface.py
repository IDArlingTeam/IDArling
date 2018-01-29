import logging

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel  # type: ignore

from ..module import Module
from .actions import OpenAction, SaveAction
from .widgets import StatusWidget


logger = logging.getLogger('IDAConnect.Interface')


MYPY = False
if MYPY:
    from ..plugin import IDAConnect


class Interface(Module):
    """
    The interface module, responsible for all interactions with the user.
    """

    @staticmethod
    def _findMainWindow():
        # type: () -> QMainWindow
        """
        Return the main window instance using Qt.

        :return: the main window
        """
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        # type: (IDAConnect) -> None
        super(Interface, self).__init__(plugin)

        self._window = self._findMainWindow()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)

        self._labelWidget = None
        self._statusWidget = None

    def _install(self):
        # type: () -> bool
        self._installActions()
        self._installWidgets()
        return True

    def _uninstall(self):
        # type: () -> bool
        self._uninstallActions()
        self._uninstallWidgets()
        return True

    def _installActions(self):
        # type: () -> None
        """
        Install the actions: install open and save.
        """
        self._openAction.install()
        self._saveAction.install()

    def _installWidgets(self):
        # type: () -> None
        """
        Install the widgets: install label and status.
        """
        if not self._labelWidget:
            self._labelWidget = QLabel(self._plugin.description())
            self._window.statusBar().addPermanentWidget(self._labelWidget)

        if not self._statusWidget:
            self._statusWidget = StatusWidget(self._plugin)
            self._window.statusBar().addPermanentWidget(self._statusWidget)

        logger.debug("Installed widgets in status bar")

    def _uninstallActions(self):
        # type: () -> None
        """
        Uninstall the actions: uninstall open and save.
        """
        self._openAction.uninstall()
        self._saveAction.uninstall()

    def _uninstallWidgets(self):
        # type: () -> None
        """
        Uninstall the widgets: uninstall label and status.
        """
        if self._labelWidget:
            self._window.statusBar().removeWidget(self._labelWidget)

        if self._statusWidget:
            self._window.statusBar().removeWidget(self._statusWidget)

        logger.debug("Uninstalled widgets from status bar")

    def _updateActions(self):
        # type: () -> None
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def notifyDisconnected(self):
        # type: () -> None
        """
        Notify the user that a disconnection has occurred. This will mainly
        cause the status widget to update its display.
        """
        if self._statusWidget:
            self._statusWidget.setState(StatusWidget.STATE_DISCONNECTED)
            self._statusWidget.setServer(StatusWidget.SERVER_DISCONNECTED)
        self._updateActions()

    def notifyConnecting(self):
        # type: () -> None
        """
        Notify the user that a connection is being established. This will
        mainly cause the status widget to update its display.
        """
        if self._statusWidget:
            self._statusWidget.setState(StatusWidget.STATE_CONNECTING)
            self._statusWidget.setServer(self._plugin.network.host)
        self._updateActions()

    def notifyConnected(self):
        # type: () -> None
        """
        Notify the user that a connection has being established. This will
        mainly cause the status widget to update its display.
        """
        if self._statusWidget:
            self._statusWidget.setState(StatusWidget.STATE_CONNECTED)
        self._updateActions()
