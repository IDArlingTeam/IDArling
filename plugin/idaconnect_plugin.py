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

        self._install_ui()
        self.core.install()
        self.network.install()

    def _term(self):
        self._uninstall_ui()
        self.core.uninstall()
        self.network.uninstall()

    def _install_ui(self):
        self._install_open_action()
        self._install_save_action()

    def _uninstall_ui(self):
        self._uninstall_open_action()
        self._uninstall_save_action()

    ACTION_OPEN = 'idaconnect:open'
    ACTION_SAVE = 'idaconnect:save'

    def _install_open_action(self):
        class OpenActionHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        icon_path = plugin_resource('open.png')
        icon_data = str(open(icon_path, 'rb').read())
        self._icon_id_open = idaapi.load_custom_icon(data=icon_data)

        action_desc = idaapi.action_desc_t(
            self.ACTION_OPEN,
            "Open from server...",
            OpenActionHandler(),
            None,
            "Load a database from the server",
            self._icon_id_open
        )

        result = idaapi.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register open action")

        result = idaapi.attach_action_to_menu(
            'File/Open...',
            self.ACTION_OPEN,
            idaapi.SETMENU_APP
        )
        if not result:
            RuntimeError("Failed to attach open action")

        logger.info("Installed the 'Open from server' menu entry")

    def _uninstall_open_action(self):
        result = idaapi.detach_action_from_menu(
            'File/Open...',
            self.ACTION_OPEN
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_OPEN)
        if not result:
            return False

        idaapi.free_custom_icon(self._icon_id_open)
        self._icon_id_open = idaapi.BADADDR

        logger.info("Uninstalled the 'Open from server' menu entry")

    def _install_save_action(self):
        class SaveActionHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        icon_path = plugin_resource('save.png')
        icon_data = str(open(icon_path, 'rb').read())
        self._icon_id_save = idaapi.load_custom_icon(data=icon_data)

        action_desc = idaapi.action_desc_t(
            self.ACTION_SAVE,
            "Save to server...",
            SaveActionHandler(),
            None,
            "Save the database to the server",
            self._icon_id_save
        )

        result = idaapi.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register save action")

        result = idaapi.attach_action_to_menu(
            'File/Save...',
            self.ACTION_SAVE,
            idaapi.SETMENU_APP
        )
        if not result:
            RuntimeError("Failed to attach save action")

        logger.info("Installed the 'Save to server' menu entry")

    def _uninstall_save_action(self):
        result = idaapi.detach_action_from_menu(
            'File/Save...',
            self.ACTION_SAVE
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_SAVE)
        if not result:
            return False

        idaapi.free_custom_icon(self._icon_id_save)
        self._icon_id_save = idaapi.BADADDR

        logger.info("Uninstalled the 'Save to server' menu entry")

    def _print_banner(self):
        params = PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_AUTHORS
        banner = "%s v%s - (c) %s" % params

        log("")
        log("-" * 75)
        log(banner)
        log("-" * 75)
        log("")
