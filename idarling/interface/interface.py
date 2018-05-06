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
import random

import ida_funcs
import ida_kernwin
import ida_nalt
import ida_pro
import idautils

from PyQt5.QtCore import QObject, Qt, QRect, QCoreApplication
from PyQt5.QtGui import QShowEvent, QPixmap, QImage, QColor
from PyQt5.QtWidgets import QApplication, QMainWindow,\
                            QDialog, QGroupBox, QLabel, QWidget

from ..module import Module
from .actions import OpenAction, SaveAction
from .widgets import StatusWidget

from functools import partial

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
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._window = self._find_main_window()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)
        self.DEFCOLOR = 0xFFFFFFFF
        self._cur_color = self.DEFCOLOR
        self._prev_color = self.DEFCOLOR
        self._cur_func_color = self.DEFCOLOR
        self._prev_func_color = self.DEFCOLOR
        self._nbytes = 0

        class EventHandler(QObject):

            def __init__(self, plugin, parent=None):
                super(EventHandler, self).__init__(parent)
                self._plugin = plugin

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
                return False
        self._eventFilter = EventHandler(self._plugin)
        self._statusWidget = StatusWidget(self._plugin)

        r, g, b = colorsys.hls_to_rgb(random.random(), 0.5, 1.0)
        self._color = int(r * 255) << 16 | int(g * 255) << 8 | int(b * 255)

    def _install(self):
        self._openAction.install()
        self._saveAction.install()
        self._install_our_icon()

        class UIHooks(ida_kernwin.UI_Hooks):
            def __init__(self, interface):
                self._interface = interface
                ida_kernwin.UI_Hooks.__init__(self)

            def ready_to_run(self, *_):
                interface = self._interface
                interface._default_bg = interface.get_ida_bg_color_html_code()
                colorizer = interface.colorizer
                ida_colorizer = ida_kernwin.set_nav_colorizer(colorizer)
                interface.ida_colorizer = ida_colorizer

        self._UIHooks = UIHooks(self)
        self._UIHooks.hook()

        self._window.statusBar().addPermanentWidget(self._statusWidget)
        logger.debug("Installed widgets in status bar")
        return True

    def _uninstall(self):
        self._openAction.uninstall()
        self._saveAction.uninstall()
        self._uninstall_our_icon()

        self._UIHooks.unhook()

        self._window.statusBar().removeWidget(self._statusWidget)
        logger.debug("Uninstalled widgets from status bar")
        return True

    def _update_actions(self):
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def _install_our_icon(self):
        """
        Install our icon into the about dialog.
        """
        QApplication.instance().installEventFilter(self._eventFilter)

    def _uninstall_our_icon(self):
        """
        Uninstall our icon from the about dialog.
        """
        QApplication.instance().removeEventFilter(self._eventFilter)

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
    def color(self):
        return self._color

    @property
    def nbytes(self):
        return self._nbytes

    def colorizer(self, ea, nbytes):
        orig = ida_kernwin.call_nav_colorizer(self.ida_colorizer, ea, nbytes)
        return long(orig)

    def cust_colorizer(self, users, ea, nbytes):
        self._nbytes = nbytes
        orig = ida_kernwin.call_nav_colorizer(self.ida_colorizer, ea, nbytes)
        for color, user_ea in users.items():
            if ea - nbytes * 2 <= user_ea <= ea + nbytes * 2:
                return long(color)
            if ea - nbytes * 4 <= user_ea <= ea - nbytes * 2:
                return long(0)
            if ea + nbytes * 2 <= user_ea <= ea + nbytes * 4:
                return long(0)
        return long(orig)

    def color_navbar(self, users):
        ida_kernwin.set_nav_colorizer(partial(self.cust_colorizer,
                                              users))

    def color_current_func(self, cur_func, prev_func, color):
        if cur_func:
            if prev_func and cur_func != prev_func:
                self._prev_func_color = self._cur_func_color
                self._cur_func_color = cur_func.color
            cur_func.color = color
            ida_funcs.update_func(cur_func)

    def color_func_insts(self, ea):
        for item_ea in idautils.FuncItems(ea):
            color = ida_nalt.get_item_color(item_ea)
            if color == self.DEFCOLOR:
                ida_nalt.set_item_color(item_ea, self._default_bg)

    def color_current_inst(self, ea, color):
        self._prev_color = self._cur_color
        self._cur_color = ida_nalt.get_item_color(ea)
        ida_nalt.set_item_color(ea, color)

    def clear_prev_inst(self, ea, prev_ea):
        if self._prev_color != self.DEFCOLOR and self._prev_color is not None:
            color = self._prev_color
        else:
            color = self._default_bg
        ida_nalt.set_item_color(prev_ea, color)

    def clear_prev_func_insts(self, prev_ea):
        for item_ea in idautils.FuncItems(prev_ea):
            color = ida_nalt.get_item_color(item_ea)
            ida_nalt.set_item_color(item_ea, color if color else self.DEFCOLOR)

    def clear_prev_func(self, ea, func, prev_func):
        if (not func and prev_func) or \
           (func and prev_func and prev_func != func):
            if prev_func:
                prev_func.color = self._prev_func_color
                ida_funcs.update_func(prev_func)

    def clear_current_inst(self, ea):
        if self._cur_color != self.DEFCOLOR and self._cur_color is not None:
            color = self._cur_color
        else:
            color = self._default_bg
        ida_nalt.set_item_color(ea, color)

    def clear_current_func(self, ea):
        func = ida_funcs.get_func(ea)
        if func:
            func.color = self._prev_func_color
            ida_funcs.update_func(func)

    def get_ida_bg_color_html_code(self):
        b, g, r, _ = self.get_ida_bg_color().getRgb()
        return r << 16 | g << 8 | b

    # From Markus Gaasedelen
    # https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse/util/ida.py
    def get_ida_bg_color(self):
        """
        Get the background color of an IDA disassembly view. (IDA 7+)
        """
        names = ["Enums", "Structures"]
        names += ["Hex View-%u" % i for i in range(5)]
        names += ["IDA View-%c" % chr(ord('A') + i) for i in range(5)]

        # find a form (eg, IDA view) to analyze colors from
        for window_name in names:
            twidget = ida_kernwin.find_widget(window_name)
            if twidget:
                break
        else:
            raise RuntimeError("Failed to find donor view")

        # touch the target form so we know it is populated
        self.touch_window(twidget)

        # locate the Qt Widget for a form and take 1px image slice of it
        import sip
        widget = sip.wrapinstance(long(twidget), QWidget)
        pixmap = widget.grab(QRect(0, 10, widget.width(), 1))

        # convert the raw pixmap into an image (easier to interface with)
        image = QImage(pixmap.toImage())

        # return the predicted background color
        return QColor(self.predict_bg_color(image))

    def touch_window(self, target):
        """
        Touch a window/widget/form to ensure it gets drawn by IDA.
        XXX/HACK:
          We need to ensure that widget we will analyze actually gets drawn
          so that there are colors for us to steal.
          To do this, we switch to it, and switch back. I tried a few different
          ways to trigger this from Qt, but could only trigger the full
          painting by going through the IDA routines.
        """

        # get the currently active widget/form title (the form itself seems
        # transient...)
        twidget = ida_kernwin.get_current_widget()
        title = ida_kernwin.get_widget_title(twidget)

        # touch the target window by switching to it
        ida_kernwin.activate_widget(target, True)
        self.flush_ida_sync_requests()

        # locate our previous selection
        previous_twidget = ida_kernwin.find_widget(title)

        # return us to our previous selection
        ida_kernwin.activate_widget(previous_twidget, True)
        self.flush_ida_sync_requests()

    def predict_bg_color(self, image):
        """
        Predict the background color of an IDA View from a given image slice.
        We hypothesize that the 'background color' of a given image slice of an
        IDA form will be the color that appears in the longest 'streaks' or
        continuous sequences. This will probably be true 99% of the time.
        This function takes an image, and analyzes its first row of pixels. It
        will return the color that it believes to be the 'background color'
        based on its sequence length.
        """
        assert image.width() and image.height()

        # the details for the longest known color streak will be saved in these
        longest = 1
        speculative_bg = image.pixel(0, 0)

        # this will be the computed length of the current color streak
        sequence = 1

        # find the longest streak of color in a single pixel slice
        for x in xrange(1, image.width()):

            # the color of this pixel matches the last pixel, extend the streak
            # count
            if image.pixel(x, 0) == image.pixel(x-1, 0):
                sequence += 1

                #
                # this catches the case where the longest color streak is in
                # fact the last one. this ensures the streak color will get
                # saved.

                if x != image.width():
                    continue

            # color change, determine if this was the longest continuous color
            # streak
            if sequence > longest:

                # save the last pixel as the longest seqeuence / most likely BG
                # color
                longest = sequence
                speculative_bg = image.pixel(x-1, 0)

                # reset the sequence counter
                sequence = 1

        # return the color we speculate to be the background color
        return speculative_bg

    def mainthread(f):
        """
        A debug decorator to assert main thread execution.
        """
        def wrapper(*args, **kwargs):
            assert ida_pro.is_main_thread()
            return f(*args, **kwargs)
        return wrapper

    @mainthread
    def flush_ida_sync_requests(self):
        """
        Flush all execute_sync requests.
        """

        # this will trigger/flush the IDA UI loop
        qta = QCoreApplication.instance()
        qta.processEvents()
