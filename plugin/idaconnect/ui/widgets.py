import sys   # noqa
sys.path.append('../..')  # noqa

from PyQt5.QtCore import Qt, QPoint, QSize
from PyQt5.QtGui import QPixmap, QIcon, QPainter
from PyQt5.QtWidgets import QWidget, QLabel, QMenu, QAction

from idaconnect.util import *


class StatusWidget(QWidget):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

    def __init__(self, plugin):
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        self._state = self.DISCONNECTED
        self._server = '&lt;no server&gt;'
        self._servers = ['127.0.0.1']

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._contextMenu)
        self._update()

    def _update(self):
        byState = {
            self.DISCONNECTED: ('red', 'Disconnected', 'disconnected.png'),
            self.CONNECTING: ('orange', 'Connecting', 'connecting.png'),
            self.CONNECTED: ('green', 'Connected', 'connected.png')
        }
        color, text, icon = byState[self._state]

        textFmt = '%s -- <span style="color: %s;">%s</span>'
        self._textWidget = QLabel(textFmt % (self._server, color, text))

        self._iconWidget = QLabel()
        pixmap = QPixmap(getPluginResource(icon))
        pixmapHeight = self._textWidget.sizeHint().height()
        self._iconWidget.setPixmap(pixmap.scaled(pixmapHeight, pixmapHeight,
                                                 Qt.KeepAspectRatio,
                                                 Qt.SmoothTransformation))

        size = QSize(self._textWidget.sizeHint().width() +
                     self._iconWidget.sizeHint().width(), pixmapHeight)
        self.setMinimumSize(size)
        self.setMaximumSize(size)
        self.repaint()

    def _contextMenu(self, point):
        menu = QMenu(self)
        settings = QAction('Network Settings', menu)
        iconPath = getPluginResource('settings.png')
        settings.setIcon(QIcon(iconPath))
        menu.addAction(settings)

        if self._servers:
            menu.addSeparator()
            for server in self._servers:
                isConnected = server == self._plugin.network.getHost()
                serverAction = QAction(server, menu, checkable=True)
                serverAction.setChecked(isConnected)

                def serverActionToggled(checked=False):
                    if checked:
                        self._plugin.network.connect(server, 31013)
                    else:
                        self._plugin.network.disconnect()
                serverAction.toggled.connect(serverActionToggled)
                menu.addAction(serverAction)
        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, event):
        painter = QPainter(self)
        map_ = painter.deviceTransform().map
        self._textWidget.render(painter, map_(QPoint(0, 0)))
        current = self._textWidget.sizeHint().width()
        self._iconWidget.render(painter, map_(QPoint(current, 0)))

    def setState(self, state):
        if state != self._state:
            self._state = state
            self._update()

    def setServer(self, server='&lt;no server&gt;'):
        if server != self._server:
            self._server = server
            self._update()
