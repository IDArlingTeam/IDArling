import logging

import idaapi

from idaconnect.core import Core
from idaconnect.network import Network
from idaconnect.util import *

if not logging_started():
    logger = start_logging()

PLUGIN_NAME = "IDAConnect"
PLUGIN_VERSION = "0.0.1"
PLUGIN_AUTHORS = "The IDAConnect Team"


def PLUGIN_ENTRY():
    return IDAConnect()


class IDAConnect(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        try:
            self._init()
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        self._print_banner()
        logger.info("Successfully initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.warning("IDAConnect cannot be run as a script")

    def term(self):
        try:
            self._term()
        except Exception as e:
            logger.exception("Failed to terminate properly")

        logger.info("Plugin terminated")

    def _init(self):
        self.core = Core(self)
        self.network = Network(self)

        self.core.install()
        self.network.install()

    def _term(self):
        self.core.uninstall()
        self.network.uninstall()

    def _print_banner(self):
        params = PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_AUTHORS
        banner = "%s v%s - (c) %s" % params

        log("")
        log("-" * 75)
        log(banner)
        log("-" * 75)
        log("")
