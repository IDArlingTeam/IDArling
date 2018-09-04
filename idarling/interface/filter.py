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
import ida_kernwin

from PyQt5.QtCore import QObject, Qt  # noqa: I202
from PyQt5.QtGui import QContextMenuEvent, QIcon, QImage, QPixmap, QShowEvent
from PyQt5.QtWidgets import (
    QAction,
    qApp,
    QDialog,
    QGroupBox,
    QLabel,
    QMenu,
    QWidget,
)

from .widget import StatusWidget
from ..shared.commands import InviteTo


class EventFilter(QObject):
    """
    This Qt event filter is used to replace the IDA icon with our
    own and to setup the invites context menu in the disassembler view.
    """

    def __init__(self, plugin, parent=None):
        super(EventFilter, self).__init__(parent)
        self._plugin = plugin
        self._augment = False

    def install(self):
        qApp.instance().installEventFilter(self)

    def uninstall(self):
        qApp.instance().removeEventFilter(self)

    def replace_icon(self, label):
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
        # having the title "Dialog"
        if (
            isinstance(obj, QDialog)
            and isinstance(ev, QShowEvent)
            and obj.windowTitle() == "About"
        ):
            # Look for a QGroupBox
            for child in obj.children():
                if isinstance(child, QGroupBox):
                    # Look for a QLabel with an icon
                    for subchild in child.children():
                        if isinstance(subchild, QLabel) and subchild.pixmap():
                            self.replace_icon(subchild)

        # We're looking for a QContextMenuEvent on a QWidget
        if isinstance(obj, QWidget) and isinstance(ev, QContextMenuEvent):
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
                pixmap = QPixmap(self._plugin.plugin_resource("invite.png"))
                menu.setIcon(QIcon(pixmap))

                # Setup our first submenu entry text and icon
                everyone = QAction("Everyone", menu)
                pixmap = QPixmap(self._plugin.plugin_resource("users.png"))
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
                template = QImage(self._plugin.plugin_resource("user.png"))

                def create_action(name, color):
                    action = QAction(name, menu)
                    pixmap = StatusWidget.make_icon(template, color)
                    action.setIcon(QIcon(pixmap))

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
