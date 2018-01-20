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
        self._servers = []

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self._update()

    def _update(self):
        by_state = {
            self.DISCONNECTED: ('red', 'Disconnected', 'disconnected.png'),
            self.CONNECTING: ('orange', 'Connecting', 'connecting.png'),
            self.CONNECTED: ('green', 'Connected', 'connected.png')
        }
        color, text, icon = by_state[self._state]

        text_fmt = '%s -- <span style="color: %s;">%s</span>'
        self._text_widget = QLabel(text_fmt % (self._server, color, text))

        self._icon_widget = QLabel()
        pixmap = QPixmap(plugin_resource(icon))
        pixmap_height = self._text_widget.sizeHint().height()
        self._icon_widget.setPixmap(pixmap.scaled(pixmap_height, pixmap_height,
                                                  Qt.KeepAspectRatio,
                                                  Qt.SmoothTransformation))

        size = QSize(self._text_widget.sizeHint().width() +
                     self._icon_widget.sizeHint().width(), pixmap_height)
        self.setMinimumSize(size)
        self.setMaximumSize(size)
        self.repaint()

    def _context_menu(self, point):
        menu = QMenu(self)
        settings = QAction('Network Settings', menu)
        settings.triggered.connect(  # FIXME: show network settings form
            lambda checked: self._plugin.network.connect('127.0.0.1', 31013))
        icon_path = plugin_resource('settings.png')
        settings.setIcon(QIcon(icon_path))
        menu.addAction(settings)

        if self._servers:
            menu.addSeparator()
            for server in self._servers:
                menu.addAction(server)
        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, event):
        painter = QPainter(self)
        map_ = painter.deviceTransform().map
        self._text_widget.render(painter, map_(QPoint(0, 0)))
        current = self._text_widget.sizeHint().width()
        self._icon_widget.render(painter, map_(QPoint(current, 0)))

    def set_state(self, state):
        if state != self._state:
            self._state = state
            self._update()

    def set_server(self, server='&lt;no server&gt;'):
        if server != self._server:
            self._server = server
            self._update()
