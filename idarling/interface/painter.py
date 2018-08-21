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
import collections
import colorsys
import functools
import logging
import random

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import idautils

from ..utilities.ida import get_ida_bg_color

logger = logging.getLogger('IDArling.Painter')


class Painter(object):
    """
    The painter module, responsible for all the database painting.
    This module is highly inspired by the painting module from Makus Gaasedelen
    https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse/painting.py
    """

    def __init__(self):
        """
        Initialize the painter module.
        """
        super(Painter, self).__init__()

        # ---------------------------------------------------------------------
        # Current user parameters
        # ---------------------------------------------------------------------

        # User name
        self.name = None
        # Choose a random color for the current user
        r, g, b = colorsys.hls_to_rgb(random.random(), 0.5, 1.0)
        self._color = int(r * 255) << 16 | int(g * 255) << 8 | int(b * 255)
        # User's parameters for navbar and notifications
        self.noNavbarColorizer = False
        self.noNotifications = False

        # ---------------------------------------------------------------------
        # Painted State
        # ---------------------------------------------------------------------

        #
        # self._painted_instructions:
        #   collections.defaultdict(ea: collections.deque(colors))
        #
        self._painted_instructions = collections.defaultdict(collections.deque)

        #
        # self._painted_functions:
        #   collections.defaultdict(functions: collections.deque(colors))
        #
        self._painted_functions = collections.defaultdict(collections.deque)

        self._users_positions = collections.defaultdict(dict)

        self.DEFCOLOR = 0xFFFFFFFF

        self._nbytes = 0

    def install(self):
        """
        Install the painter into the IDA UI.

        :return: did the install succeed
        """
        class UIHooks(ida_kernwin.UI_Hooks):
            def __init__(self, painter):
                self._painter = painter
                ida_kernwin.UI_Hooks.__init__(self)

            def ready_to_run(self, *_):
                """
                We must get the original ida colorizer only one time to avoid
                segfault.
                """

                #
                # get default background and original navbar colorizer
                #

                self._painter.bg_color = get_ida_bg_color()
                colorizer = self._painter.custom_nav_colorizer
                ida_nav_colorizer = ida_kernwin.set_nav_colorizer(colorizer)
                self._painter.ida_nav_colorizer = ida_nav_colorizer

        self._uiHooks = UIHooks(self)
        result = self._uiHooks.hook()
        if not result:
            raise RuntimeError("Failed to install painter")

        logger.debug("Painter installed")
        return True

    def uninstall(self):
        """
        Uninstall the painter module.

        :return: did the uninstall succeed
        """

        result = self._uiHooks.unhook()
        if not result:
            raise RuntimeError("Uninstalled the painter")

        logger.debug("Uninstalled the painter")
        return True

    def paint(self, color, address):
        """
        Request database painting

        :param color: the color to paint
        :param address: the address where apply the color
        """
        self.paint_database(color, address)

    def unpaint(self, color):
        """
        Request database unpainting

        :param color: the color to unpaint
        """
        self.unpaint_database(color)

    # -------------------------------------------------------------------------
    # Painter - Navbar colorizer
    # -------------------------------------------------------------------------

    def custom_nav_colorizer(self, ea, nbytes):
        """
        Custom navbar colorizer.
        It adds users positions in the navbar.
        """
        #
        # to ajust the black band with the navband zoom level
        # there is a bug in IDA, with huge segment number, all the navbar takes
        # the color provided by the user, this will be resolved in IDA 7.2
        #
        if not self.noNavbarColorizer:
            for color, infos in self.users_positions.items():
                if ea - nbytes * 2 <= infos['address'] <= ea + nbytes * 2:
                    return long(color)
                if ea - nbytes * 4 <= infos['address'] <= ea + nbytes * 4:
                    return long(0)
        orig = ida_kernwin.call_nav_colorizer(self.ida_nav_colorizer, ea,
                                              nbytes)

        return long(orig)

    def paint_navbar(self):
        ida_kernwin.refresh_navband(True)

    # -------------------------------------------------------------------------
    # Painter - Instructions / Items
    # -------------------------------------------------------------------------

    def paint_instruction(self, color, address):
        """
        Paint instructions with the given color

        :param color: the color
        :param address: the address where apply the color
        """
        # get current color
        current_color = self.get_paint_instruction(address)
        # store current color to color stack
        self._painted_instructions[address].append(current_color)
        # update current user position
        self.users_positions[color]['address'] = address
        # apply the user color
        self.set_paint_instruction(address, color)

    def clear_instruction(self, color):
        """
        Clear paint from the given instruction

        :param color: the color
        """
        # get user position
        users_positions = self.users_positions.get(color)
        if users_positions:
            address = users_positions['address']
            # if a color has been applied, restore it
            try:
                color = self._painted_instructions[address].pop()
            # else apply the default background
            except Exception as e:
                color = self.bg_color
            self.set_paint_instruction(address, color)

    def set_paint_instruction(self, address, color):
        """
        Wrapper around set_item_color

        :param address: the address where apply the color
        :param color: the color
        """
        ida_nalt.set_item_color(address, color)

    def get_paint_instruction(self, address):
        """
        Wrapper around get_item_color, get the color of a given address

        :param address: the address where apply the color
        """
        return ida_nalt.get_item_color(address)

    # -------------------------------------------------------------------------
    # Painter - Functions
    # -------------------------------------------------------------------------

    def paint_function(self, color, new_address):
        """
        Paint function with the given color

        :param color: the color
        :param new_address: address within the function where apply the color
        """
        #
        # paint all instructions within the function with default background
        # this has to be done because painting function paint all nodes in it
        #
        self.paint_function_instructions(new_address)
        new_func = ida_funcs.get_func(new_address)

        # get the previous user position
        user_position = self.users_positions.get(color)
        if user_position:
            address = user_position['address']
            func = ida_funcs.get_func(address)
            # paint it only if previous function and new function are different
            if not new_func or (func and new_func and func == new_func):
                return
        if new_func:
            # add the color to the new function color stack
            self._painted_functions[new_func.startEA].append(new_func.color)
            # finaly paint the function
            self.set_paint_function(new_func, color)

    def clear_function(self, color, new_address):
        """
        Clear paint from the given functions

        :param color: the color
        :param new_address: an address within the function where the color
                            needs to be cleared
        """
        user_position = self.users_positions.get(color)
        new_func = ida_funcs.get_func(new_address)

        #
        # if the deqeue is empty, this is the first time we meet this function
        # we must save the original color to restore it
        # TODO: broadcast the original color to others users
        #
        if new_func and not self._painted_functions[new_func.startEA]:
            self._painted_functions[new_func.startEA].append(new_func.color)

        if user_position:
            address = user_position['address']
            self.clear_function_instructions(address)
            func = ida_funcs.get_func(address)

            # clear it only if previous func and new func are different
            if (func and not new_func) or \
                    (func and new_func and func != new_func):
                color = self._painted_functions[func.startEA].pop()
                # if the queue is not empty, repaint all the instructions with
                # the background color
                if self._painted_functions[func.startEA]:
                    self.paint_function_instructions(address)
                self.set_paint_function(func, color)

    def paint_function_instructions(self, address):
        """
        Paint function instructions with the user-defined background color

        :param address: an address within the function
        """
        for start_ea, end_ea in idautils.Chunks(address):
            for ea in idautils.Heads(start_ea, end_ea):
                color = self.get_paint_instruction(ea)
                # color only instructions that aren't colored yet to keep
                # user-defined color
                if color == self.DEFCOLOR:
                    self.set_paint_instruction(ea, self.bg_color)
                else:
                    #
                    # TODO: IDA doesn't provide a way to hook painting, with
                    # this we can propagate user-defined colors between users.
                    #
                    pass

    def clear_function_instructions(self, address):
        """
        Clear function instructions

        :param address: an address within the function
        """
        for start_ea, end_ea in idautils.Chunks(address):
            for ea in idautils.Heads(start_ea, end_ea):
                color = self.get_paint_instruction(ea)
                # clear only if it's not colorized by user
                color = color if color != self.bg_color else self.DEFCOLOR
                self.set_paint_instruction(ea, color)

    def set_paint_function(self, function, color):
        """
        Set function color

        :param function: the function to colorize
        :param color: the color
        """
        function.color = color
        ida_funcs.update_func(function)

    # -------------------------------------------------------------------------
    # Painter
    # -------------------------------------------------------------------------

    def paint_database(self, color, address):
        """
        Update database's paint state with the given color and address

        :param color: the color
        :param address: the address
        """
        # clear instructions
        self.clear_instruction(color)
        # clear functions
        self.clear_function(color, address)
        # paint functions
        self.paint_function(color, address)
        # paint instructions
        self.paint_instruction(color, address)
        # paint navbar
        self.paint_navbar()

    def unpaint_database(self, color):
        """
        Clear paint associated with the given color and update state

        :param color: the color
        """
        # clear instructions
        self.clear_instruction(color)
        self.clear_function(color, ida_idaapi.BADADDR)

    #
    # methods used by saving and saved hooks
    #
    def clear_database(self, address):
        """
        Clear paint for the given address. It's used when the idb is about to
        be saved.

        :param address: the address
        :return: the color
        """
        color = self.get_paint_instruction(address)
        self.set_paint_instruction(address, self.DEFCOLOR)
        func = ida_funcs.get_func(address)
        if func:
            self.set_paint_function(func, self.DEFCOLOR)
        return color

    def repaint_database(self, color, address):
        """
        Repaint the address with the given color. It's used when the idb as
        been saved.

        :param color: the color
        :param address: the address to colorized
        """
        self.set_paint_instruction(address, color)
        func = ida_funcs.get_func(address)
        if func:
            self.set_paint_function(func, color)

    # -------------------------------------------------------------------------
    # Misc
    # -------------------------------------------------------------------------

    @property
    def color(self):
        """
        Get the color local user.

        :return: the color
        """
        return self._color

    @color.setter
    def color(self, color):
        """
        Set the color of the local user.

        :param color: the color
        """
        self._color = color

    @property
    def nbytes(self):
        """
        Get nbytes.

        :return: nbytes
        """
        return self._nbytes

    @property
    def users_positions(self):
        """
        Return the current users positions

        :return: the current users positions
        """
        return self._users_positions
