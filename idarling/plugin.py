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
import ida_idaapi
import ida_kernwin

from PyQt5.QtCore import QCoreApplication

from .core.core import Core
from .interface.interface import Interface
from .network.network import Network
from .utilities.log import start_logging
from .utilities.misc import plugin_resource

# Start logging
logger = start_logging()


class Plugin(ida_idaapi.plugin_t):
    """
    The IDArling plugin.
    """
    # Internal definitions
    PLUGIN_NAME = "IDArling"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "The IDArling Team"

    # External definitions
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    @staticmethod
    def description():
        """
        Get the plugin description (name and version).

        :return: the description
        """
        return "{} v{}".format(Plugin.PLUGIN_NAME,
                               Plugin.PLUGIN_VERSION)

    @staticmethod
    def resource(filename):
        """
        Get the absolute path to a resource.

        :param filename: the filename
        :return: the path
        """
        return plugin_resource(filename)

    def __init__(self):
        """
        Instantiate the plugin and all its modules.
        """
        if QCoreApplication.instance() is None:
            raise RuntimeError("IDArling cannot be used in terminal mode")

        self._core = Core(self)
        self._interface = Interface(self)
        self._network = Network(self)

    @property
    def core(self):
        """
        Get the core module.

        :return: the core module
        """
        return self._core

    @property
    def interface(self):
        """
        Get the interface module.

        :return: the interface module
        """
        return self._interface

    @property
    def network(self):
        """
        Get the network module.

        :return: the network module
        """
        return self._network

    def init(self):
        """
        This method is called when IDA is loading the plugin.

        :return: should the plugin be kept
        """
        try:
            self._init()
        except Exception as e:
            logger.error("Failed to initialize")
            logger.exception(e)
            skip = ida_idaapi.PLUGIN_SKIP
            return skip

        self._print_banner()
        logger.info("Successfully initialized")
        keep = ida_idaapi.PLUGIN_KEEP
        return keep

    def _init(self):
        """
        Initialize the plugin and all its modules.
        """
        self._interface.install()
        self._network.install()
        self._core.install()

    def _print_banner(self):
        """
        Print the banner into the console.
        """
        copyright = "(c) %s" % self.PLUGIN_AUTHORS

        logger.info("-" * 75)
        logger.info("%s - %s" % (self.description(), copyright))
        logger.info("-" * 75)

    def term(self):
        """
        This method is called when IDA is unloading the plugin.
        """
        try:
            self._term()
        except Exception as e:
            logger.error("Failed to terminate properly")
            logger.exception(e)
            return

        logger.info("Terminated properly")

    def _term(self):
        """
        Terminate the plugin and its modules.
        """
        self._core.uninstall()
        self._network.uninstall()
        self._interface.uninstall()

    def run(self, _):
        """
        This method is called when IDA is running the plugin as a script.
        """
        ida_kernwin.warning("IDArling cannot be run as a script")
        return False

    def notify_disconnected(self):
        """
        Notify the plugin that a disconnection has occurred.
        """
        self._core.notify_disconnected()
        self._interface.notify_disconnected()
        self._network.notify_disconnected()

    def notify_connecting(self):
        """
        Notify the plugin that a connection is being established.
        """
        self._core.notify_connecting()
        self._interface.notify_connecting()
        self._network.notify_connecting()

    def notify_connected(self):
        """
        Notify the plugin that a connection has been established.
        """
        self._core.notify_connected()
        self._interface.notify_connected()
        self._network.notify_connected()
