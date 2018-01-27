import os
import logging

import idaapi

# Import all the modules
from idaconnect.core.core import Core
from idaconnect.interface.interface import Interface
from idaconnect.network.network import Network

# Import utilities
from idaconnect.utilities.log import loggingStarted, startLogging
from idaconnect.utilities.misc import pluginResource

# Start logging if necessary
if not loggingStarted():
    logger = startLogging()

# -----------------------------------------------------------------------------
# IDA Plugin
# -----------------------------------------------------------------------------


def PLUGIN_ENTRY():
    return IDAConnect()


class IDAConnect(idaapi.plugin_t):
    PLUGIN_NAME = "IDAConnect"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "The IDAConnect Team"

    # Definitions required for a IDA plug-in
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        # Instantiate all the modules
        self._core = Core(self)
        self._interface = Interface(self)
        self._network = Network(self)

    # -------------------------------------------------------------------------
    # Modules
    # -------------------------------------------------------------------------

    def getCore(self):
        return self._core

    def getInterface(self):
        return self._interface

    def getNetwork(self):
        return self._network

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def init(self):
        # Try to initialize the plug-in
        try:
            self._init()
        except Exception:
            # Initialization failed
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        # Initialization successful
        self._printBanner()
        logger.info("Successfully initialized")
        return idaapi.PLUGIN_KEEP

    def _init(self):
        # Install all the modules
        self._core.install()
        self._interface.install()
        self._network.install()

    def _printBanner(self):
        # Print a nice banner for our users
        copyright = "(c) %s" % self.PLUGIN_AUTHORS

        prefix = '[IDAConnect] '
        print prefix + ("-" * 75)
        print prefix + "%s - %s" % (self.getDescription(), copyright)
        print prefix + ("-" * 75)

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def term(self):
        # Try to terminate the plug-in
        try:
            self._term()
        except Exception:
            # Termination failed
            logger.exception("Failed to terminate properly")

        # Termination successful
        logger.info("Terminated properly")

    def _term(self):
        # Uninstall all the modules
        self._core.uninstall()
        self._interface.uninstall()
        self._network.uninstall()

    # -------------------------------------------------------------------------
    # Execution
    # -------------------------------------------------------------------------

    def run(self, arg):
        idaapi.warning("IDAConnect cannot be run as a script")

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def getDescription(self):
        return "%s v%s" % (self.PLUGIN_NAME, self.PLUGIN_VERSION)

    def getResource(self, resource):
        return pluginResource(resource)

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def notifyDisconnected(self):
        self._interface.notifyDisconnected()

    def notifyConnecting(self):
        self._interface.notifyConnecting()

    def notifyConnected(self):
        self._interface.notifyConnected()
