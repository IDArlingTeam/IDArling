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
import sys

import ida_funcs
import ida_kernwin

from PyQt5.QtCore import (  # noqa: I202
    QAbstractItemModel,
    QModelIndex,
    QObject,
    Qt,
)
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QStyledItemDelegate, QWidget
import sip

from .widget import StatusWidget

if sys.version_info > (3,):
    long = int


class Painter(QObject):
    class ProxyItemDelegate(QStyledItemDelegate):
        def __init__(self, delegate, model, parent=None):
            super(Painter.ProxyItemDelegate, self).__init__(parent)
            self._delegate = delegate
            self._model = model

        def paint(self, painter, option, index):
            index = self._model.index(index.row(), index.column())
            self._delegate.paint(painter, option, index)

    class ProxyItemModel(QAbstractItemModel):
        def __init__(self, model, plugin, parent=None):
            super(Painter.ProxyItemModel, self).__init__(parent)
            self._model = model
            self._plugin = plugin

        def index(self, row, column, parent=QModelIndex()):
            return self.createIndex(row, column)

        def parent(self, index):
            index = self._model.index(index.row(), index.column())
            return self._model.parent(index)

        def rowCount(self):  # noqa: N802
            return self._model.rowCount()

        def columnCount(self):  # noqa: N802
            return self._model.columnCount()

        def data(self, index, role=Qt.DisplayRole):
            # Check if disabled by the user
            cursors = self._plugin.config["cursors"]
            if role == Qt.BackgroundRole and cursors["funcs"]:
                func_ea = int(index.sibling(index.row(), 2).data(), 16)
                func = ida_funcs.get_func(func_ea)
                for user in self._plugin.core.get_users().values():
                    if ida_funcs.func_contains(func, user["ea"]):
                        r, g, b = StatusWidget.ida_to_python(user["color"])
                        return QColor(StatusWidget.python_to_qt(r, g, b))
            index = self._model.index(index.row(), index.column())
            return self._model.data(index, role)

    def __init__(self, plugin):
        super(Painter, self).__init__()
        self._plugin = plugin

        self._ida_nav_colorizer = None
        self._nbytes = 0

    def nav_colorizer(self, ea, nbytes):
        """This is the custom nav colorizer used by the painter."""
        self._nbytes = nbytes

        # There is a bug in IDA: with a huge number of segments, all the navbar
        # is colored with the user color. This will be resolved in IDA 7.2.
        cursors = self._plugin.config["cursors"]
        if cursors["navbar"]:
            for user in self._plugin.core.get_users().values():
                # Cursor color
                if ea - nbytes * 2 <= user["ea"] <= ea + nbytes * 2:
                    return long(user["color"])
                # Cursor borders
                if ea - nbytes * 4 <= user["ea"] <= ea + nbytes * 4:
                    return long(0)
        orig = ida_kernwin.call_nav_colorizer(
            self._ida_nav_colorizer, ea, nbytes
        )
        return long(orig)

    def ready_to_run(self):
        # The default nav colorized can only be recovered once!
        ida_nav_colorizer = ida_kernwin.set_nav_colorizer(self.nav_colorizer)
        if ida_nav_colorizer is not None:
            self._ida_nav_colorizer = ida_nav_colorizer
        self.refresh()

    def get_ea_hint(self, ea):
        cursors = self._plugin.config["cursors"]
        if not cursors["navbar"]:
            return None

        for name, user in self._plugin.core.get_users().items():
            start_ea = user["ea"] - self._nbytes * 4
            end_ea = user["ea"] + self._nbytes * 4
            # Check if the navbar range contains the user's address
            if start_ea <= ea <= end_ea:
                return str(name)

    def get_bg_color(self, ea):
        # Check if disabled by the user
        cursors = self._plugin.config["cursors"]
        if not cursors["disasm"]:
            return None

        for user in self._plugin.core.get_users().values():
            if ea == user["ea"]:
                return user["color"]
        return None

    def widget_visible(self, twidget):
        widget = sip.wrapinstance(long(twidget), QWidget)
        if widget.windowTitle() != "Functions window":
            return
        table = widget.layout().itemAt(0).widget()

        # Replace the table's item delegate
        model = Painter.ProxyItemModel(table.model(), self._plugin, self)
        old_deleg = table.itemDelegate()
        new_deleg = Painter.ProxyItemDelegate(old_deleg, model, self)
        table.setItemDelegate(new_deleg)

    def refresh(self):
        ida_kernwin.refresh_navband(True)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_FUNCS)
