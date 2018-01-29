import idaapi  # type: ignore

from .core.core import Core
from .interface.interface import Interface
from .network.network import Network

from .utilities.log import startLogging
from .utilities.misc import pluginResource


# Start logging
logger = startLogging()


class IDAConnect(idaapi.plugin_t):  # type: ignore
    """
    The IDAConnect plugin.
    """
    # Internal definitions
    PLUGIN_NAME = "IDAConnect"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "The IDAConnect Team"

    # External definitions
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    @staticmethod
    def description():
        # type: () -> str
        """
        Get the plugin description (name and version).

        :return: the description
        """
        return "{} v{}".format(IDAConnect.PLUGIN_NAME,
                               IDAConnect.PLUGIN_VERSION)

    @staticmethod
    def resource(filename):
        # type: (str) -> str
        """
        Get the absolute path to a resource.

        :param filename: the filename
        :return: the path
        """
        return pluginResource(filename)

    def __init__(self):
        # type: () -> None
        """
        Instantiate the plugin and all its modules.
        """
        self._core = Core(self)
        self._interface = Interface(self)
        self._network = Network(self)

    @property
    def core(self):
        # type: () -> Core
        """
        Get the core module.

        :return: the core module
        """
        return self._core

    @property
    def interface(self):
        # type: () -> Interface
        """
        Get the interface module.

        :return: the interface module
        """
        return self._interface

    @property
    def network(self):
        # type: () -> Network
        """
        Get the network module.

        :return: the network module
        """
        return self._network

    def init(self):
        # type: () -> int
        """
        This method is called when IDA is loading the plugin.

        :return: should the plugin be kept
        """
        try:
            self._init()
        except Exception:
            logger.exception("Failed to initialize")
            skip = idaapi.PLUGIN_SKIP  # type: int
            return skip

        self._printBanner()
        logger.info("Successfully initialized")
        keep = idaapi.PLUGIN_KEEP  # type: int
        return keep

    def _init(self):
        # type: () -> None
        """
        Initialize the plugin and all its modules.
        """
        self._core.install()
        self._interface.install()
        self._network.install()

    def _printBanner(self):
        # type: () -> None
        """
        Print the banner into the console.
        """
        copyright = "(c) %s" % self.PLUGIN_AUTHORS

        prefix = '[IDAConnect] '
        print prefix + ("-" * 75)
        print prefix + "%s - %s" % (self.description(), copyright)
        print prefix + ("-" * 75)

    def term(self):
        # type: () -> None
        """
        This method is called when IDA is unloading the plugin.
        """
        try:
            self._term()
        except Exception:
            logger.exception("Failed to terminate properly")

        logger.info("Terminated properly")

    def _term(self):
        # type: () -> None
        """
        Terminate the plugin and its modules.
        """
        self._core.uninstall()
        self._interface.uninstall()
        self._network.uninstall()

    def run(self, _):
        # type: (int) -> bool
        """
        This method is called when IDA is running the plugin as a script.
        """
        idaapi.warning("IDAConnect cannot be run as a script")
        return False

    def notifyDisconnected(self):
        # type: () -> None
        """
        Notify the plugin that a disconnection has occurred.
        """
        self._interface.notifyDisconnected()

    def notifyConnecting(self):
        # type: () -> None
        """
        Notify the plugin that a connection is being established.
        """
        self._interface.notifyConnecting()

    def notifyConnected(self):
        # type: () -> None
        """
        Notify the plugin that a connection has been established.
        """
        self._interface.notifyConnected()
