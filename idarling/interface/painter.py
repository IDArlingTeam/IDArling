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
import struct
import sys

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_registry
import idautils

if sys.version_info > (3,):
    long = int


class Painter(object):
    """The painter module is responsible for all the database painting."""

    DEFCOLOR = 0xffffffff

    @staticmethod
    def _get_ida_bg_color():
        """
        Return the background color from the disassembly view. It uses the
        IDA registry to recover the color palettes configured by the user. Then
        it loads the background color from the currently active palette.
        """
        palette = ida_registry.reg_read_binary("Palette")
        if palette is None:
            return 0xffffff
        selected = struct.unpack("<I", palette[8:12])[0]
        index = 176 + selected * 208
        return struct.unpack("<I", palette[index : index + 4])[0]  # noqa: E203

    @staticmethod
    def _get_paint_instruction(address):
        """This is wrapper around get_item_color."""
        return ida_nalt.get_item_color(address)

    @staticmethod
    def _set_paint_instruction(address, color):
        """This is a wrapper around set_item_color."""
        ida_nalt.set_item_color(address, color)

    @staticmethod
    def _get_paint_function(function):
        return function.color

    @staticmethod
    def _set_paint_function(function, color):
        """Set a function's color."""
        function.color = color
        ida_funcs.update_func(function)

    @staticmethod
    def _paint_navbar():
        """Request a repainting of the navbar."""
        ida_kernwin.refresh_navband(True)

    def __init__(self, plugin):
        super(Painter, self).__init__()
        self._plugin = plugin
        self._installed = False

        self._painted_instructions = collections.defaultdict(collections.deque)
        self._painted_functions = collections.defaultdict(collections.deque)
        self._users_positions = collections.defaultdict(dict)

    @property
    def installed(self):
        """Is the painter active?"""
        return self._installed

    @property
    def users_positions(self):
        """Return the position and color of connected users."""
        return self._users_positions

    def install(self):
        self._reset()
        self._installed = True
        self._plugin.logger.debug("Painter installed")
        return True

    def uninstall(self):
        self._reset()
        self._installed = False
        self._plugin.logger.debug("Painter uninstalled")
        return True

    def _reset(self):
        self._painted_instructions.clear()
        self._painted_functions.clear()
        self._users_positions.clear()

    def clear(self):
        # Remove everybody
        names = list(self._users_positions.keys())
        for name in names:
            self.unpaint(name)
        self._reset()

    def set_custom_nav_colorizer(self):
        # The default nav colorized can only be recovered once!
        colorizer = self.custom_nav_colorizer
        ida_nav_colorizer = ida_kernwin.set_nav_colorizer(colorizer)
        if ida_nav_colorizer is not None:
            self._ida_nav_colorizer = ida_nav_colorizer
        self._bg_color = Painter._get_ida_bg_color()

    def paint(self, name, color, address):
        """Request a painting of the specified address."""
        self.paint_database(name, color, address)

    def unpaint(self, name):
        """Request a repainting when the user has left."""
        self.unpaint_database(name)
        self._users_positions.pop(name)

    def custom_nav_colorizer(self, ea, nbytes):
        """This is the custom nav colorizer used by the painter."""
        # There is a bug in IDA: with a huge number of segments, all the navbar
        # is colored with the user color. This will be resolved in IDA 7.2.
        if self._plugin.config["user"]["navbar_colorizer"]:
            for infos in self._users_positions.values():
                if ea - nbytes * 2 <= infos["address"] <= ea + nbytes * 2:
                    return long(infos["color"])
                if ea - nbytes * 4 <= infos["address"] <= ea + nbytes * 4:
                    return long(0)
        orig = ida_kernwin.call_nav_colorizer(
            self._ida_nav_colorizer, ea, nbytes
        )
        return long(orig)

    def paint_instruction(self, name, color, address):
        """Paint a instruction with the specified color."""
        # Get current color
        current_color = self._get_paint_instruction(address)
        # Store current color into the stack
        self._painted_instructions[address].append(current_color)
        # Update the user position and name
        self._users_positions[name]["address"] = address
        self._users_positions[name]["color"] = color
        # Apply the user color
        self._set_paint_instruction(address, color)

    def clear_instruction(self, name):
        """Clear the paint from the specified user."""
        # Get the user position
        users_positions = self._users_positions.get(name)
        if users_positions:
            address = users_positions["address"]
            # If a color has been applied, restore it
            try:
                color = self._painted_instructions[address].pop()
            # Otherwise apply the default background color
            except IndexError:
                color = self._bg_color
            self._set_paint_instruction(address, color)

    def paint_function(self, name, color, new_address):
        """Paints a function with the specified color."""
        # Paint all instructions within the function with default background.
        # This has to be done because painting function paint all nodes in it.
        self.paint_function_instructions(new_address)
        new_func = ida_funcs.get_func(new_address)

        # Get the user previous position
        user_position = self._users_positions.get(name)
        if user_position:
            address = user_position["address"]
            func = ida_funcs.get_func(address)
            # Paint it only if previous function and new function are different
            if not new_func or (func and new_func and func == new_func):
                return
        if new_func:
            # Add the color to the new function color stack
            func_color = self._get_paint_function(new_func)
            self._painted_functions[new_func.start_ea].append(func_color)
            # Finally paint the function
            self._set_paint_function(new_func, color)

    def clear_function(self, name, new_address):
        """Clear paint from the specified user and function."""
        user_position = self._users_positions.get(name)
        new_func = ida_funcs.get_func(new_address)

        # If the stack is empty, this is the first time we meet this function,
        # so we must save the original color to restore it.
        if new_func and not self._painted_functions[new_func.start_ea]:
            func_color = self._get_paint_function(new_func)
            self._painted_functions[new_func.start_ea].append(func_color)

        if user_position:
            address = user_position["address"]
            self.clear_function_instructions(address)
            func = ida_funcs.get_func(address)

            # Clear it only if previous func and new func are different
            if (func and not new_func) or (
                func and new_func and func != new_func
            ):
                color = self._painted_functions[func.start_ea].pop()
                # If the stack is not empty, repaint all the instructions with
                # the color popped from the stack.
                if self._painted_functions[func.start_ea]:
                    self.paint_function_instructions(address)
                self._set_paint_function(func, color)

    def paint_function_instructions(self, address):
        """Paint a function's instructions with the user color."""
        for start_ea, end_ea in idautils.Chunks(address):
            for ea in idautils.Heads(start_ea, end_ea):
                color = self._get_paint_instruction(ea)
                # Only color instructions that aren't colored yet to keep
                # an existing user-defined color
                if color == self.DEFCOLOR:
                    self._set_paint_instruction(ea, self._bg_color)

    def clear_function_instructions(self, address):
        """Clear paint from a function instructions."""
        for start_ea, end_ea in idautils.Chunks(address):
            for ea in idautils.Heads(start_ea, end_ea):
                color = self._get_paint_instruction(ea)
                # Clear it only if it hasn't been colorized by the user
                color = color if color != self._bg_color else self.DEFCOLOR
                self._set_paint_instruction(ea, color)

    def paint_database(self, name, color, address):
        """Update the painting when an user has moved to another address."""
        # Clear the instruction
        self.clear_instruction(name)
        # Clear the function
        self.clear_function(name, address)
        # Paint the function
        self.paint_function(name, color, address)
        # Paint the instruction
        self.paint_instruction(name, color, address)
        # Paint the navbar
        self._paint_navbar()

    def unpaint_database(self, name):
        """Clear paint associated with the specified name."""
        self.clear_instruction(name)
        self.clear_function(name, ida_idaapi.BADADDR)

    def clear_database(self, address):
        """
        This method is called when the database is about to be saved to avoid
        saving the cursor into it. It will clear paint from the given address.
        """
        color = self._get_paint_instruction(address)
        self._set_paint_instruction(address, self.DEFCOLOR)
        func = ida_funcs.get_func(address)
        if func:
            self._set_paint_function(func, self.DEFCOLOR)
        return color

    def repaint_database(self, color, address):
        """
        This method is called when the database has finished saving to restore
        the cursors into it. It will restore paint for the given address.
        """
        self._set_paint_instruction(address, color)
        func = ida_funcs.get_func(address)
        if func:
            self._set_paint_function(func, color)

    def rename_user(self, old_name, new_name):
        """Notifies the painter that an user has been renamed."""
        self._users_positions[new_name] = self._users_positions.pop(old_name)

    def change_user_color(self, name, old_color, new_color):
        """Notifies the painter that an user has changed color."""
        # Replace the color for the given user
        self._users_positions[name]["color"] = new_color

        # Replace the color in painted instructions for the given user
        user_address = self._users_positions[name]["address"]
        for n, e in enumerate(self._painted_instructions[user_address]):
            if e == old_color:
                self._painted_instructions[user_address][n] = new_color
        # If the color is the current color instruction (not in the stack yet),
        # repaint the given instruction with the new color
        if new_color not in self._painted_instructions[user_address]:
            self._set_paint_instruction(user_address, new_color)

        # Replace the color in painted functions for the given user
        func = ida_funcs.get_func(user_address)
        if func:
            for n, e in enumerate(self._painted_functions[func.start_ea]):
                if e == old_color:
                    self._painted_functions[func.start_ea][n] = new_color

            # If the color is the current color function (not in the stack
            # yet, repaint the given function with the new color
            if new_color not in self._painted_functions[user_address]:
                self._set_paint_function(func, new_color)
