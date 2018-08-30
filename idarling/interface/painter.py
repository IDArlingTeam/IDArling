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
import logging
import random
import struct

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_registry
import idautils

logger = logging.getLogger('IDArling.Painter')


class Painter(object):
    """
    The painter module, responsible for all the database painting.
    This module is highly inspired by the painting module from Makus Gaasedelen
    https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse/painting.py
    """

    @staticmethod
    def get_ida_bg_color():
        palette = ida_registry.reg_read_binary("Palette")
        if palette is None:
            return 0xffffff
        selected = struct.unpack("<I", palette[8:12])[0]
        index = 176 + selected * 208
        return struct.unpack("<I", palette[index:index + 4])[0]

    def __init__(self, plugin):
        """
        Initialize the painter module.
        """
        super(Painter, self).__init__()
        self._plugin = plugin

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

        #
        # self._users_positions:
        #   collections.defaultdict({name: {color: int, address: int}}
        #
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
                ida_kernwin.UI_Hooks.__init__(self)
                self._painter = painter

            def ready_to_run(self, *_):
                """
                We must get the original ida colorizer only one time to avoid
                segfault.
                """

                #
                # get default background and original navbar colorizer
                #

                colorizer = self._painter.custom_nav_colorizer
                ida_nav_colorizer = ida_kernwin.set_nav_colorizer(colorizer)
                if ida_nav_colorizer is not None:
                    self._painter.ida_nav_colorizer = ida_nav_colorizer
                self._painter.bg_color = Painter.get_ida_bg_color()

        self._uiHooks = UIHooks(self)
        result = self._uiHooks.hook()

        # ---------------------------------------------------------------------
        # Current user parameters
        # ---------------------------------------------------------------------

        # Choose a random color for the current user if it's not user-defined

        if self._plugin.config["user"]["color"] == -1:
            r, g, b = colorsys.hls_to_rgb(random.random(), 0.5, 1.0)
            color = int(b * 255) << 16 | int(g * 255) << 8 | int(r * 255)
            self._plugin.config["user"]["color"] = color
            self._plugin.save_config()

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

    def paint(self, name, color, address):
        """
        Request database painting

        :param name: the user's name
        :param color: the color to paint
        :param address: the address where apply the color
        """
        self.paint_database(name, color, address)

    def unpaint(self, name):
        """
        Request database unpainting

        :param name: the user to remove
        """
        self.unpaint_database(name)

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
        if self._plugin.config["user"]["navbar_colorizer"]:
            for infos in self._users_positions.values():
                if ea - nbytes * 2 <= infos['address'] <= ea + nbytes * 2:
                    return long(infos['color'])
                if ea - nbytes * 4 <= infos['address'] <= ea + nbytes * 4:
                    return long(0)
        orig = ida_kernwin.call_nav_colorizer(self.ida_nav_colorizer, ea,
                                              nbytes)
        self.nbytes = nbytes
        return long(orig)

    def paint_navbar(self):
        """
        Request a repainting for the navbar
        """
        ida_kernwin.refresh_navband(True)

    # -------------------------------------------------------------------------
    # Painter - Instructions / Items
    # -------------------------------------------------------------------------

    def paint_instruction(self, name, color, address):
        """
        Paint instructions with the given color

        :param color: the color
        :param name: the user name
        :param address: the address where apply the color
        """
        # get current color
        current_color = self.get_paint_instruction(address)
        # store current color to color stack
        self._painted_instructions[address].append(current_color)
        # update current user position and name
        self.users_positions[name]["address"] = address
        self.users_positions[name]["color"] = color
        # apply the user color
        self.set_paint_instruction(address, color)

    def clear_instruction(self, name):
        """
        Clear paint from the given instruction

        :param name: the name
        """
        # get user position
        users_positions = self.users_positions.get(name)
        if users_positions:
            address = users_positions['address']
            # if a color has been applied, restore it
            try:
                color = self._painted_instructions[address].pop()
            # else apply the default background
            except IndexError:
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

    def paint_function(self, name, color, new_address):
        """
        Paint function with the given color

        :param name: the name
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
        user_position = self.users_positions.get(name)
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

    def clear_function(self, name, new_address):
        """
        Clear paint from the given functions

        :param name: the name
        :param new_address: an address within the function where the color
                            needs to be cleared
        """
        user_position = self.users_positions.get(name)
        new_func = ida_funcs.get_func(new_address)

        #
        # if the deqeue is empty, this is the first time we meet this function
        # we must save the original color to restore it
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

    def paint_database(self, name, color, address):
        """
        Update database's paint state with the given color and address

        :param name: the name
        :param color: the color
        :param address: the address
        """
        # clear instructions
        self.clear_instruction(name)
        # clear functions
        self.clear_function(name, address)
        # paint functions
        self.paint_function(name, color, address)
        # paint instructions
        self.paint_instruction(name, color, address)
        # paint navbar
        self.paint_navbar()

    def unpaint_database(self, name):
        """
        Clear paint associated with the given name and update state

        :param name: the name
        """
        # clear instructions
        self.clear_instruction(name)
        self.clear_function(name, ida_idaapi.BADADDR)

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

    #
    # methods used by user_color_changed user_renamed events handlers
    #
    def rename_user(self, old_name, new_name):
        """
        Rename an user.

        :param old_name: the previous name
        :param new_name: the new name
        """
        self._users_positions[new_name] = self._users_positions.pop(old_name)

    def change_user_color(self, name, old_color, new_color):
        """
        Change the color for the given user

        :param name: the user name
        :param old_color: the previous color
        :param new_color: the new color
        """
        # Replace the color for the given user
        self._users_positions[name]["color"] = new_color

        # Replace the color in painted instructions for the given user
        user_address = self._users_positions[name]["address"]
        for n, e in enumerate(self._painted_instructions[user_address]):
            if e == old_color:
                self._painted_instructions[user_address][n] = new_color
        # If the color is the current color instruction (not in the deque yet)
        # repaint the given instrution with the new color
        if new_color not in self._painted_instructions[user_address]:
            self.set_paint_instruction(user_address, new_color)

        # Replace the color in painted functions for the given user
        func = ida_funcs.get_func(user_address)
        if func:
            for n, e in enumerate(self._painted_functions[func.start_ea]):
                if e == old_color:
                    self._painted_functions[func.start_ea][n] = new_color
        # If the color is the current color function (not in the deque yet)
        # repaint the given function with the new color
        if new_color not in self._painted_functions[user_address]:
            self.set_paint_function(func, new_color)

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

    @nbytes.setter
    def nbytes(self, nbytes):
        """
        Set nbytes.

        :param nbytes: nbytes
        """
        self._nbytes = nbytes

    @property
    def users_positions(self):
        """
        Return the current users positions
        :return: the current users positions
        """
        return self._users_positions
