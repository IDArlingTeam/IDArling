import logging

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

from ..module import Module
from actions import OpenAction, SaveAction
from widgets import StatusWidget


logger = logging.getLogger('IDAConnect.Interface')

# -----------------------------------------------------------------------------
# Interface Module
# -----------------------------------------------------------------------------


class Interface(Module):

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)

        # Find the main window
        self._window = self._findMainWindow()

        # Initialize actions
        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)

        # Initialize widgets
        self._labelWidget = None
        self._statusWidget = None

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def _install(self):
        self._installActions()
        self._installWidgets()

    def _installActions(self):
        self._openAction.install()
        self._saveAction.install()

    def _installWidgets(self):
        # Install the label widget
        if not self._labelWidget:
            self._labelWidget = QLabel(self._plugin.getDescription())
            self._window.statusBar().addPermanentWidget(self._labelWidget)

        # Install the status widget
        if not self._statusWidget:
            self._statusWidget = StatusWidget(self._plugin)
            self._window.statusBar().addPermanentWidget(self._statusWidget)

        logger.debug("Installed widgets in status bar")

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def _uninstall(self):
        self._uninstallActions()
        self._uninstallWidgets()
        return True

    def _uninstallActions(self):
        self._openAction.uninstall()
        self._saveAction.uninstall()

    def _uninstallWidgets(self):
        # Uninstall label widget
        if self._labelWidget:
            self._window.statusBar().removeWidget(self._labelWidget)

        # Uninstall status widget
        if self._statusWidget:
            self._window.statusBar().removeWidget(self._statusWidget)

        logger.debug("Uninstalled widgets from status bar")

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    def _findMainWindow(self):
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def _updateActions(self):
        self._openAction.update()
        self._saveAction.update()

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def notifyDisconnected(self):
        self._statusWidget.setState(StatusWidget.STATE_DISCONNECTED)
        self._statusWidget.setServer(StatusWidget.SERVER_DISCONNECTED)
        self._updateActions()

    def notifyConnecting(self):
        self._statusWidget.setState(StatusWidget.STATE_CONNECTING)
        self._statusWidget.setServer(self._plugin.getNetwork().getHost())
        self._updateActions()

    def notifyConnected(self):
        self._statusWidget.setState(StatusWidget.STATE_CONNECTED)
        self._updateActions()
