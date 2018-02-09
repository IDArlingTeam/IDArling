import json
import os

import idaapi

from core.core import Core
from interface.interface import Interface
from network.network import Network

from utilities.log import startLogging
from utilities.misc import localResource, pluginResource

# Start logging
logger = startLogging()


class IDAConnect(idaapi.plugin_t):
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
        """
        Get the plugin description (name and version).

        :return: the description
        """
        return "{} v{}".format(IDAConnect.PLUGIN_NAME,
                               IDAConnect.PLUGIN_VERSION)

    @staticmethod
    def resource(filename):
        """
        Get the absolute path to a resource.

        :param filename: the filename
        :return: the path
        """
        return pluginResource(filename)

    def __init__(self):
        """
        Instantiate the plugin and all its modules.
        """
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
        except Exception:
            logger.exception("Failed to initialize")
            skip = idaapi.PLUGIN_SKIP
            return skip

        self._printBanner()
        logger.info("Successfully initialized")
        keep = idaapi.PLUGIN_KEEP
        return keep

    def _init(self):
        """
        Initialize the plugin and all its modules.
        """
        self._core.install()
        self._interface.install()
        self._network.install()

        # Load the current state
        self.loadState()

    def _printBanner(self):
        """
        Print the banner into the console.
        """
        copyright = "(c) %s" % self.PLUGIN_AUTHORS

        prefix = '[IDAConnect] '
        print prefix + ("-" * 75)
        print prefix + "%s - %s" % (self.description(), copyright)
        print prefix + ("-" * 75)

    def term(self):
        """
        This method is called when IDA is unloading the plugin.
        """
        try:
            self._term()
        except Exception:
            logger.exception("Failed to terminate properly")

        logger.info("Terminated properly")

    def _term(self):
        """
        Terminate the plugin and its modules.
        """
        self._core.uninstall()
        self._interface.uninstall()
        self._network.uninstall()

    def run(self, _):
        """
        This method is called when IDA is running the plugin as a script.
        """
        idaapi.warning("IDAConnect cannot be run as a script")
        return False

    def notifyDisconnected(self):
        """
        Notify the plugin that a disconnection has occurred.
        """
        self._interface.notifyDisconnected()

    def notifyConnecting(self):
        """
        Notify the plugin that a connection is being established.
        """
        self._interface.notifyConnecting()

    def notifyConnected(self):
        """
        Notify the plugin that a connection has been established.
        """
        self._interface.notifyConnected()

    def loadState(self):
        """
        Load the state file if it exists.
        """
        statePath = localResource('files', 'state.json')
        if os.path.isfile(statePath):
            with open(statePath, 'rb') as stateFile:
                state = json.loads(stateFile.read())
                if state['connected']:
                    self.network.connect(state['host'], state['port'])
            os.remove(statePath)

    def saveState(self):
        """
        Save the state file.
        """
        statePath = localResource('files', 'state.json')
        with open(statePath, 'wb') as stateFile:
            state = {
                'connected': self.network.connected,
                'host': self.network.host,
                'port': self.network.port,
            }
            stateFile.write(json.dumps(state))
