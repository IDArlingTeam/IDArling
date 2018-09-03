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
from PyQt5.QtCore import QPoint, QRect, QSize, Qt
from PyQt5.QtGui import QIcon, QPainter, QPixmap, QRegion
from PyQt5.QtWidgets import QAction, QActionGroup, QLabel, QMenu, QWidget

from .dialogs import SettingsDialog


class StatusWidget(QWidget):
    """
    This is the widget that is displayed in the status bar of the window. It
    allow the user to connect to server, as well as to access the settings.
    """

    STATE_DISCONNECTED = 0
    STATE_CONNECTING = 1
    STATE_CONNECTED = 2

    def __init__(self, plugin):
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        self._state = self.STATE_DISCONNECTED
        self._server = None

        # Create the sub-widgets
        self._text_widget = QLabel()
        self._text_widget.setAutoFillBackground(False)
        self._text_widget.setAttribute(Qt.WA_PaintOnScreen)
        self._text_widget.setAttribute(Qt.WA_TranslucentBackground)

        self._icon_widget = QLabel()
        self._icon_widget.setAutoFillBackground(False)
        self._icon_widget.setAttribute(Qt.WA_PaintOnScreen)
        self._icon_widget.setAttribute(Qt.WA_TranslucentBackground)

        # Set a custom context menu policy
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.update_widget()

    def update_widget(self):
        """Called to update the widget when the network state has changed."""
        self._plugin.logger.debug("Updating widget state")

        # Get the corresponding color, text and icon
        if self._state == StatusWidget.STATE_DISCONNECTED:
            color, text, icon = "red", "Disconnected", "disconnected.png"
        elif self._state == StatusWidget.STATE_CONNECTING:
            color, text, icon = "orange", "Connecting", "connecting.png"
        elif self._state == StatusWidget.STATE_CONNECTED:
            color, text, icon = "green", "Connected", "connected.png"
        else:
            self._plugin.logger.warning("Invalid server state")
            return

        # Update the text of the widget
        if self._server is None:
            server = "&lt;no server&gt;"
        else:
            server = "%s:%d" % (self._server["host"], self._server["port"])
        text_format = '%s | %s -- <span style="color: %s;">%s</span>'
        self._text_widget.setText(
            text_format % (self._plugin.description(), server, color, text)
        )
        self._text_widget.adjustSize()

        # Update the icon of the widget
        pixmap = QPixmap(self._plugin.plugin_resource(icon))
        pixmap_height = self._text_widget.sizeHint().height()
        self._icon_widget.setPixmap(
            pixmap.scaled(
                pixmap_height,
                pixmap_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

        # Update the size of the widget
        self.updateGeometry()

    def sizeHint(self):  # noqa: N802
        """Called when the widget size is being determined internally."""
        width = self._text_widget.sizeHint().width()
        width += 6 + self._icon_widget.sizeHint().width()
        return QSize(width, self._text_widget.sizeHint().height())

    def _context_menu(self, point):
        """Called when the context menu is being populated."""
        self._plugin.logger.debug("Opening widget context menu")
        menu = QMenu(self)

        # Add the settings action
        settings = QAction("Settings...", menu)
        icon_path = self._plugin.plugin_resource("settings.png")
        settings.setIcon(QIcon(icon_path))

        # Add a handler on the action
        def settings_action_triggered():
            SettingsDialog(self._plugin).exec_()

        settings.triggered.connect(settings_action_triggered)
        menu.addAction(settings)

        # Add the integrated server action
        menu.addSeparator()
        integrated = QAction("Integrated Server", menu)
        integrated.setCheckable(True)

        def integrated_action_triggered():
            # Start or stop the server
            if integrated.isChecked():
                self._plugin.network.start_server()
            else:
                self._plugin.network.stop_server()

        integrated.setChecked(self._plugin.network.server_running())
        integrated.triggered.connect(integrated_action_triggered)
        menu.addAction(integrated)

        def create_servers_group(servers):
            """Create an action group for the specified servers."""
            servers_group = QActionGroup(self)
            current_server = self._plugin.network.server

            for server in servers:
                is_connected = (
                    self._plugin.network.connected
                    and server["host"] == current_server["host"]
                    and server["port"] == current_server["port"]
                )
                server_text = "%s:%d" % (server["host"], server["port"])
                server_action = QAction(server_text, menu)
                server_action._server = server
                server_action.setCheckable(True)
                server_action.setChecked(is_connected)
                servers_group.addAction(server_action)

            def server_action_triggered(server_action):
                """
                Called when a action is clicked. Connects to the new server
                or disconnects from the old server.
                """
                was_connected = (
                    self._plugin.network.connected
                    and self._plugin.network.server == server
                )
                self._plugin.network.stop_server()
                self._plugin.network.disconnect()
                if not was_connected:
                    self._plugin.network.connect(server_action._server)

            servers_group.triggered.connect(server_action_triggered)

            return servers_group

        # Add the discovered servers
        servers = self._plugin.network.discovery.servers
        if (
            self._plugin.network.server_running()
            and self._plugin.network.server in servers
        ):
            servers.remove(self._plugin.network.server)
        if servers:
            menu.addSeparator()
            servers_group = create_servers_group(servers)
            menu.addActions(servers_group.actions())

        # Add the configured servers
        servers = self._plugin.config["servers"]
        if self._plugin.config["servers"]:
            menu.addSeparator()
            servers_group = create_servers_group(servers)
            menu.addActions(servers_group.actions())

        # Show the context menu
        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, event):  # noqa: N802
        """Called when the widget is being painted."""
        # Adjust the buffer size according to the pixel ratio
        dpr = self.devicePixelRatioF()
        buffer = QPixmap(self.width() * dpr, self.height() * dpr)
        buffer.setDevicePixelRatio(dpr)
        buffer.fill(Qt.transparent)

        painter = QPainter(buffer)
        region = QRegion(
            QRect(
                0,
                0,
                self._text_widget.sizeHint().width(),
                self._text_widget.sizeHint().height(),
            )
        )
        # Paint the text widget
        self._text_widget.render(painter, QPoint(0, 0), region)
        region = QRegion(
            QRect(
                0,
                0,
                self._icon_widget.sizeHint().width(),
                self._icon_widget.sizeHint().height(),
            )
        )
        # Paint the icon widget
        x = self._text_widget.sizeHint().width() + 3
        self._icon_widget.render(painter, QPoint(x, 0), region)
        painter.end()

        painter = QPainter(self)
        painter.drawPixmap(event.rect(), buffer, buffer.rect())
        painter.end()

    def set_state(self, state):
        """Informs the widget of the networking state."""
        if state != self._state:
            self._state = state
            self.update_widget()

    def set_server(self, server):
        """Inform the widget of the server we're connected to."""
        if server != self._server:
            self._server = server
            self.update_widget()
