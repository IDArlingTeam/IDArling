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

import ida_kernwin

from PyQt5.QtCore import QObject, Qt  # noqa: I202
from PyQt5.QtGui import QContextMenuEvent, QIcon, QImage, QPixmap, QShowEvent
from PyQt5.QtWidgets import (
    QAction,
    qApp,
    QDialog,
    QGroupBox,
    QLabel,
    QMainWindow,
    QMenu,
    QWidget,
)

from .actions import OpenAction, SaveAction
from .painter import Painter
from .toasts import Toast
from .widgets import StatusWidget
from ..module import Module
from ..shared.commands import InviteTo


class Interface(Module):
    """
    This is the interface module. It is responsible for all interactions with
    the user interface. It manages the all the actions, dialog, cursors, toasts
    notifications and status bar widget.
    """

    @staticmethod
    def _find_main_window():
        """Find the QMainWindow instance."""
        for widget in qApp.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._window = self._find_main_window()

        # Instantiate the plugin actions
        self._open_action = OpenAction(plugin)
        self._save_action = SaveAction(plugin)
        self._painter = Painter(plugin)

        class EventHandler(QObject):
            """
            This Qt event handler is used to replace the IDA icon with our
            own and to setup the invites context menu in the disassembler view.
            """

            def __init__(self, plugin, parent=None):
                super(EventHandler, self).__init__(parent)
                self._plugin = plugin
                self._augment = False

            @staticmethod
            def replace_icon(label):
                pixmap = QPixmap(self._plugin.plugin_resource("idarling.png"))
                pixmap = pixmap.scaled(
                    label.sizeHint().width(),
                    label.sizeHint().height(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
                label.setPixmap(pixmap)

            def eventFilter(self, obj, ev):  # noqa: N802
                # We're looking for a QShowEvent being triggered on a QDialog
                if isinstance(obj, QDialog) and isinstance(ev, QShowEvent):
                    # Is it the About dialog?
                    if obj.windowTitle() == "About":
                        # Look for a QGroupBox
                        for child in obj.children():
                            if isinstance(child, QGroupBox):
                                # Look for a QLabel with an icon
                                for subchild in child.children():
                                    if (
                                        isinstance(subchild, QLabel)
                                        and subchild.pixmap()
                                    ):
                                        EventHandler.replace_icon(subchild)

                # We're looking for a QContextMenuEvent on a QWidget
                if isinstance(obj, QWidget) and isinstance(
                    ev, QContextMenuEvent
                ):
                    # Look for a parent object named "IDA View"
                    parent = obj
                    while parent:
                        if parent.windowTitle().startswith("IDA View"):
                            # Intercept the next context menu
                            self._augment = True
                        parent = parent.parent()

                # We're looking for a QShowEvent on a QMenu
                if isinstance(obj, QMenu) and isinstance(ev, QShowEvent):
                    # Is it the disassembler context menu?
                    if self._augment:
                        # Find where to install our submenu
                        sep = 0
                        for act in obj.actions():
                            if act.isSeparator():
                                sep = act
                            if "Undefine" in act.text():
                                break
                        obj.insertSeparator(sep)

                        # Setup our custom menu text and icon
                        menu = QMenu("Invite to location", obj)
                        pixmap = QPixmap(
                            self._plugin.plugin_resource("invite.png")
                        )
                        menu.setIcon(QIcon(pixmap))

                        # Setup our first submenu entry text and icon
                        everyone = QAction("Everyone", menu)
                        pixmap = QPixmap(
                            self._plugin.plugin_resource("users.png")
                        )
                        everyone.setIcon(QIcon(pixmap))

                        def invite_to(name):
                            """
                            Send an invitation to the current location within
                            the disassembler view to the specified user.
                            """
                            loc = ida_kernwin.get_screen_ea()
                            packet = InviteTo(name, loc)
                            self._plugin.network.send_packet(packet)

                        # Handler for when the action is clicked
                        def invite_to_everyone():
                            invite_to("everyone")

                        everyone.triggered.connect(invite_to_everyone)
                        menu.addAction(everyone)

                        menu.addSeparator()
                        template = QImage(
                            self._plugin.plugin_resource("user.png")
                        )

                        def ida_to_python(c):
                            # IDA colors are 0xBBGGRR.
                            r = (c & 255) / 255.
                            g = ((c >> 8) & 255) / 255.
                            b = ((c >> 16) & 255) / 255.
                            return r, g, b

                        def python_to_qt(r, g, b):
                            # Qt colors are 0xRRGGBB
                            r = int(r * 255) << 16
                            g = int(g * 255) << 8
                            b = int(b * 255)
                            return 0xff000000 | r | g | b

                        def create_action(name, color):
                            """
                            Create an action for the specified user and the
                            specified color. The color will be used to generate
                            on the fly an icon representing the user.
                            """
                            # Get a light and dark version of the user color
                            r, g, b = ida_to_python(color)
                            h, l, s = colorsys.rgb_to_hls(r, g, b)
                            r, g, b = colorsys.hls_to_rgb(h, 0.5, 1.0)
                            light = python_to_qt(r, g, b)
                            r, g, b = colorsys.hls_to_rgb(h, 0.25, 1.0)
                            dark = python_to_qt(r, g, b)

                            # Replace the icon pixel with our two colors
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

                            # Handler for when the action is clicked
                            def invite_to_user():
                                invite_to(name)

                            action.triggered.connect(invite_to_user)
                            return action

                        # Insert an action for each connected user
                        painter = self._plugin.interface.painter
                        for name, info in painter.users_positions.items():
                            menu.addAction(create_action(name, info["color"]))
                        obj.insertMenu(sep, menu)
                        self._augment = False
                return False

        self._event_filter = EventHandler(self._plugin)
        self._status_widget = StatusWidget(self._plugin)

    @property
    def painter(self):
        """Get the painter instance."""
        return self._painter

    def _install(self):
        self._painter.install()
        self._open_action.install()
        self._save_action.install()
        qApp.instance().installEventFilter(self._event_filter)
        self._window.statusBar().addPermanentWidget(self._status_widget)
        self._plugin.logger.debug("Installed widgets in status bar")
        return True

    def _uninstall(self):
        self._painter.uninstall()
        self._open_action.uninstall()
        self._save_action.uninstall()
        qApp.instance().removeEventFilter(self._event_filter)
        self._window.statusBar().removeWidget(self._status_widget)
        self._plugin.logger.debug("Uninstalled widgets from status bar")
        return True

    def _update_actions(self):
        """Update the actions status (enabled or not)."""
        self._open_action.update()
        self._save_action.update()

    def show_notification(self, text, icon, callback):
        """
        Display a toast notification to the user. The notification will have
        the specified text, icon and callback function (triggered on click).
        """
        if not self._plugin.config["user"]["notifications"]:
            return
        toast = Toast(self._window)
        toast.set_text(text)
        toast.set_icon(icon)
        toast.set_callback(callback)
        toast.show()

    def notify_disconnected(self):
        # Update the widget's state
        self._status_widget.set_state(StatusWidget.STATE_DISCONNECTED)
        self._status_widget.set_server(None)
        self._update_actions()

    def notify_connecting(self):
        # Update the widget's state
        self._status_widget.set_state(StatusWidget.STATE_CONNECTING)
        self._status_widget.set_server(self._plugin.network.server)
        self._update_actions()

    def notify_connected(self):
        # Update the widget's state
        self._status_widget.set_state(StatusWidget.STATE_CONNECTED)
        self._update_actions()
