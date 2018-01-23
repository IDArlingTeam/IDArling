import logging

from PyQt5.QtCore import Qt, QPoint, QSize
from PyQt5.QtGui import QPixmap, QIcon, QPainter
from PyQt5.QtWidgets import QWidget, QLabel, QMenu, QAction


logger = logging.getLogger('IDAConnect.Interface')

# -----------------------------------------------------------------------------
# Widgets
# -----------------------------------------------------------------------------


class StatusWidget(QWidget):
    SERVER_DISCONNECTED = '&lt;no server&gt;'

    STATE_DISCONNECTED = 0
    STATE_CONNECTING = 1
    STATE_CONNECTED = 2

    def __init__(self, plugin):
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        self._state = self.STATE_DISCONNECTED
        self._server = self.SERVER_DISCONNECTED
        self._servers = ['127.0.0.1']

        # Register custom context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._contextMenu)
        self._update()

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def _update(self):
        # Update the whole widget
        logger.debug("Updating widget state")
        byState = {
            self.STATE_DISCONNECTED: ('red', 'Disconnected',
                                      'disconnected.png'),
            self.STATE_CONNECTING: ('orange', 'Connecting', 'connecting.png'),
            self.STATE_CONNECTED: ('green', 'Connected', 'connected.png')
        }
        color, text, icon = byState[self._state]

        # Update the text first
        textFmt = '%s -- <span style="color: %s;">%s</span>'
        self._textWidget = QLabel(textFmt % (self._server, color, text))

        # Then update the icon
        self._iconWidget = QLabel()
        pixmap = QPixmap(self._plugin.getResource(icon))
        pixmapHeight = self._textWidget.sizeHint().height()
        self._iconWidget.setPixmap(pixmap.scaled(pixmapHeight, pixmapHeight,
                                                 Qt.KeepAspectRatio,
                                                 Qt.SmoothTransformation))

        # Finally resize the widget
        size = QSize(self._textWidget.sizeHint().width() + 6 +
                     self._iconWidget.sizeHint().width(), pixmapHeight)
        self.setMinimumSize(size)
        self.setMaximumSize(size)
        self.repaint()

    def _contextMenu(self, point):
        # Show the context menu
        logger.debug("Opening widget context menu")
        menu = QMenu(self)

        # Add the network settings
        settings = QAction('Network Settings', menu)
        iconPath = self._plugin.getResource('settings.png')
        settings.setIcon(QIcon(iconPath))
        menu.addAction(settings)

        # Add all the servers
        if self._servers:
            menu.addSeparator()
            for server in self._servers:
                isConnected = self._plugin.getNetwork().isConnected() \
                    and server == self._plugin.getNetwork().getHost()
                serverAction = QAction(server, menu, checkable=True)
                serverAction.setChecked(isConnected)

                # Add handler on server action
                def serverActionToggled(checked=False):
                    if checked:
                        self._plugin.getNetwork().connect(server, 31013)
                    else:
                        self._plugin.getNetwork().disconnect()

                serverAction.toggled.connect(serverActionToggled)
                menu.addAction(serverAction)

        # Execute the context menu
        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, event):
        # Override the pain event
        painter = QPainter(self)
        # Paint the text
        map_ = painter.deviceTransform().map
        self._textWidget.render(painter, map_(QPoint(0, 0)))
        # Paint the icon
        current = self._textWidget.sizeHint().width() + 3
        self._iconWidget.render(painter, map_(QPoint(current, 0)))

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def setState(self, state):
        # Change the state
        if state != self._state:
            self._state = state
            self._update()

    def setServer(self, server):
        # Change the server
        if server != self._server:
            self._server = server
            self._update()
