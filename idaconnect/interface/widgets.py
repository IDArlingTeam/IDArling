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

from PyQt5.QtCore import Qt, QSize, QPoint
from PyQt5.QtGui import QPixmap, QIcon, QPainter
from PyQt5.QtWidgets import QWidget, QLabel, QMenu, QActionGroup, QAction

from .dialogs import NetworkSettingsDialog

logger = logging.getLogger('IDAConnect.Interface')


class StatusWidget(QWidget):
    """
    The widget that displays the status of the connection to the server.
    """
    SERVER_DISCONNECTED = '&lt;no server&gt;'

    # States enumeration
    STATE_DISCONNECTED = 0
    STATE_CONNECTING = 1
    STATE_CONNECTED = 2

    def __init__(self, plugin):
        """
        Initialize the status widget.

        :param plugin: the plugin instance
        """
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        self._state = self.STATE_DISCONNECTED
        self._server = self.SERVER_DISCONNECTED

        # Set a custom context menu policy
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self._update()

    def _update(self):
        """
        Called to update the widget when its state has changed.
        """
        logger.debug("Updating widget state")

        # Get color, text and icon from state
        byState = {
            self.STATE_DISCONNECTED: ('red', 'Disconnected',
                                      'disconnected.png'),
            self.STATE_CONNECTING: ('orange', 'Connecting', 'connecting.png'),
            self.STATE_CONNECTED: ('green', 'Connected', 'connected.png')
        }
        color, text, icon = byState[self._state]

        # Update the text of the widget
        textFmt = '%s -- <span style="color: %s;">%s</span>'
        self._textWidget = QLabel(textFmt % (self._server, color, text))
        self._textWidget.setAutoFillBackground(False)
        self._textWidget.setAttribute(Qt.WA_PaintOnScreen)
        self._textWidget.setAttribute(Qt.WA_TranslucentBackground)

        # Update the icon of the widget
        self._iconWidget = QLabel()
        self._iconWidget.setAutoFillBackground(False)
        self._iconWidget.setAttribute(Qt.WA_PaintOnScreen)
        self._iconWidget.setAttribute(Qt.WA_TranslucentBackground)
        pixmap = QPixmap(self._plugin.resource(icon))
        pixmapHeight = self._textWidget.sizeHint().height()
        self._iconWidget.setPixmap(pixmap.scaled(pixmapHeight, pixmapHeight,
                                                 Qt.KeepAspectRatio,
                                                 Qt.SmoothTransformation))

        # Finally, resize the widget
        size = QSize(self._textWidget.sizeHint().width() + 6 +
                     self._iconWidget.sizeHint().width(), pixmapHeight)
        self.setMinimumSize(size)
        self.setMaximumSize(size)
        self.repaint()

    def _context_menu(self, point):
        """
        Called when the widget is right-clicked to display the context menu.

        :param point: the location where the click happened
        """
        logger.debug("Opening widget context menu")
        menu = QMenu(self)

        # Add the network settings
        settings = QAction('Network Settings', menu)
        iconPath = self._plugin.resource('settings.png')
        settings.setIcon(QIcon(iconPath))

        # Add a handler on the action
        def settingsActionTriggered():
            dialog = NetworkSettingsDialog(self._plugin)
            dialog.exec_()

        settings.triggered.connect(settingsActionTriggered)
        menu.addAction(settings)

        # Add each of the servers
        if self._plugin.core.servers:
            menu.addSeparator()
            serverGroup = QActionGroup(self)

            def serverActionTriggered(serverAction):
                if not self._plugin.network.connected and \
                       serverAction.isChecked():
                    self._plugin.network.connect(serverAction._server.host,
                                                 serverAction._server.port)
                else:
                    self._plugin.network.disconnect()

            for server in self._plugin.core.servers:
                isConnected = self._plugin.network.connected \
                              and server.host == self._plugin.network.host \
                              and server.port == self._plugin.network.port
                serverAction = QAction('%s:%d' % (server.host, server.port),
                                       menu, checkable=True)
                serverAction._server = server
                serverAction.setChecked(isConnected)
                serverGroup.addAction(serverAction)

            menu.addActions(serverGroup.actions())
            serverGroup.triggered.connect(serverActionTriggered)

        # Show the context menu
        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, _):
        """
        Called when the widget is painted on the window.
        """
        painter = QPainter(self)
        # Paint the text first
        map = painter.deviceTransform().map
        self._textWidget.render(painter, map(QPoint(0, 0)))
        # Then paint the icon
        current = self._textWidget.sizeHint().width() + 3
        self._iconWidget.render(painter, map(QPoint(current, 0)))

    def set_state(self, state):
        """
        Set the state of the connection.

        :param state: the new state
        """
        if state != self._state:
            self._state = state
            self._update()

    def set_server(self, server):
        """
        Set the server we're connected to.

        :param server: the server host
        """
        if server != self._server:
            self._server = server
            self._update()
