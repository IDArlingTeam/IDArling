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
import colorsys
import logging

import ida_kernwin

from PyQt5.QtCore import Qt, QObject
from PyQt5.QtGui import QContextMenuEvent, QIcon, QImage, QShowEvent, QPixmap
from PyQt5.QtWidgets import qApp, QAction, QDialog, QGroupBox, QLabel, \
    QMainWindow, QMenu, QWidget

from ..module import Module
from ..shared.commands import InviteTo
from .actions import OpenAction, SaveAction
from .painter import Painter
from .toasts import Toast
from .widgets import StatusWidget

logger = logging.getLogger('IDArling.Interface')


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
        for widget in qApp.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._window = self._find_main_window()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)
        self._painter = Painter(plugin)

        class EventHandler(QObject):

            def __init__(self, plugin, parent=None):
                super(EventHandler, self).__init__(parent)
                self._plugin = plugin
                self._augment = False

            @staticmethod
            def replace_icon(label):
                pixmap = QPixmap(self._plugin.resource('idarling.png'))
                pixmap = pixmap.scaled(
                    label.sizeHint().width(), label.sizeHint().height(),
                    Qt.KeepAspectRatio, Qt.SmoothTransformation)
                label.setPixmap(pixmap)

            def eventFilter(self, obj, ev):
                if isinstance(obj, QDialog) and isinstance(ev, QShowEvent):
                    if obj.windowTitle() == 'About':
                        for child in obj.children():
                            if isinstance(child, QGroupBox):
                                for subchild in child.children():
                                    if isinstance(subchild, QLabel) \
                                            and subchild.pixmap():
                                        EventHandler.replace_icon(subchild)

                if isinstance(obj, QWidget) \
                        and isinstance(ev, QContextMenuEvent):
                    parent = obj
                    while parent:
                        if parent.windowTitle().startswith("IDA View"):
                            self._augment = True
                        parent = parent.parent()

                if isinstance(obj, QMenu) and isinstance(ev, QShowEvent):
                    if self._augment:
                        sep = 0
                        for act in obj.actions():
                            if act.isSeparator():
                                sep = act
                            if "Undefine" in act.text():
                                break

                        obj.insertSeparator(sep)
                        menu = QMenu("Invite to location", obj)
                        pixmap = QPixmap(self._plugin.resource('invite.png'))
                        menu.setIcon(QIcon(pixmap))

                        everyone = QAction("Everyone", menu)
                        pixmap = QPixmap(self._plugin.resource('users.png'))
                        everyone.setIcon(QIcon(pixmap))

                        def inviteTo(name):
                            loc = ida_kernwin.get_screen_ea()
                            packet = InviteTo(name, loc)
                            self._plugin.network.send_packet(packet)

                        def inviteToEveryone():
                            inviteTo("everyone")
                        everyone.triggered.connect(inviteToEveryone)
                        menu.addAction(everyone)

                        menu.addSeparator()
                        template = QImage(self._plugin.resource('user.png'))

                        def ida_to_python(c):
                            r = (c & 255) / 255.
                            g = ((c >> 8) & 255) / 255.
                            b = ((c >> 16) & 255) / 255.
                            return r, g, b

                        def python_to_qt(r, g, b):
                            r = int(r * 255) << 16
                            g = int(g * 255) << 8
                            b = int(b * 255)
                            return 0xff000000 | r | g | b

                        def create_action(name, color):
                            r, g, b = ida_to_python(color)
                            h, l, s = colorsys.rgb_to_hls(r, g, b)
                            r, g, b = colorsys.hls_to_rgb(h, 0.5, 1.0)
                            light = python_to_qt(r, g, b)
                            r, g, b = colorsys.hls_to_rgb(h, 0.25, 1.0)
                            dark = python_to_qt(r, g, b)

                            image = QImage(template)
                            for x in range(image.width()):
                                for y in range(image.height()):
                                    c = image.pixel(x, y)
                                    if (c & 0xffffff) == 0xffffff:
                                        image.setPixel(x, y, light)
                                    if (c & 0xffffff) == 0x000000:
                                        image.setPixel(x, y, dark)

                            action = QAction(name, menu)
                            action.setIcon(QIcon(QPixmap(image)))

                            def inviteToUser():
                                inviteTo(name)
                            action.triggered.connect(inviteToUser)
                            return action

                        painter = self._plugin.interface.painter
                        for name, info in painter.users_positions.items():
                            menu.addAction(create_action(name, info["color"]))
                        obj.insertMenu(sep, menu)
                        self._augment = False
                return False
        self._eventFilter = EventHandler(self._plugin)
        self._statusWidget = StatusWidget(self._plugin)

    def _install(self):
        self._openAction.install()
        self._saveAction.install()
        self._install_event_filter()
        self._painter.install()

        self._window.statusBar().addPermanentWidget(self._statusWidget)
        logger.debug("Installed widgets in status bar")
        return True

    def _uninstall(self):
        self._openAction.uninstall()
        self._saveAction.uninstall()
        self._uninstall_event_filter()
        self._painter.uninstall()

        self._window.statusBar().removeWidget(self._statusWidget)
        logger.debug("Uninstalled widgets from status bar")
        return True

    def _update_actions(self):
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def _install_event_filter(self):
        """
        Install the Qt event filter.
        """
        qApp.instance().installEventFilter(self._eventFilter)

    def _uninstall_event_filter(self):
        """
        Uninstall the Qt event filter.
        """
        qApp.instance().removeEventFilter(self._eventFilter)

    def show_notification(self, text, icon, callback):
        if not self._plugin.config["user"]["notifications"]:
            return
        toast = Toast(self._window)
        toast.setText(text)
        toast.setIcon(icon)
        toast.setCallback(callback)
        toast.show()

    def notify_disconnected(self):
        self._statusWidget.set_state(StatusWidget.STATE_DISCONNECTED)
        self._statusWidget.set_server(None)
        self._update_actions()

    def notify_connecting(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTING)
        self._statusWidget.set_server(self._plugin.network.server)
        self._update_actions()

    def notify_connected(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTED)
        self._update_actions()

    @property
    def painter(self):
        return self._painter
