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
        self._install_download_action()
        self._install_upload_action()

    def _uninstall_ui(self):
        self._uninstall_download_action()
        self._uninstall_upload_action()

    ACTION_DOWNLOAD = 'idaconnect:download'
    ACTION_UPLOAD = 'idaconnect:upload'

    def _install_download_action(self):
        class DownloadHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        icon_path = plugin_resource('download.png')
        icon_data = str(open(icon_path, 'rb').read())
        self._icon_id_download = idaapi.load_custom_icon(data=icon_data)

        action_desc = idaapi.action_desc_t(
            self.ACTION_DOWNLOAD,
            "~D~ownload from server...",
            DownloadHandler(),
            None,
            "Load a database from the remote server",
            self._icon_id_download
        )

        result = idaapi.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register download action")

        result = idaapi.attach_action_to_menu(
            'File/Open...',
            self.ACTION_DOWNLOAD,
            idaapi.SETMENU_APP
        )
        if not result:
            RuntimeError("Failed to attach download action")

        logger.info("Installed the 'Download from server' menu entry")

    def _uninstall_download_action(self):
        result = idaapi.detach_action_from_menu(
            'File/Open...',
            self.ACTION_DOWNLOAD
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_DOWNLOAD)
        if not result:
            return False

        idaapi.free_custom_icon(self._icon_id_download)
        self._icon_id_download = idaapi.BADADDR

        logger.info("Uninstalled the 'Download from server' menu entry")

    def _install_upload_action(self):
        class UploadHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        icon_path = plugin_resource('upload.png')
        icon_data = str(open(icon_path, 'rb').read())
        self._icon_id_upload = idaapi.load_custom_icon(data=icon_data)

        action_desc = idaapi.action_desc_t(
            self.ACTION_UPLOAD,
            "~U~pload to server...",
            UploadHandler(),
            None,
            "Save a database to the remote server",
            self._icon_id_upload
        )

        result = idaapi.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register upload action")

        result = idaapi.attach_action_to_menu(
            'File/Save...',
            self.ACTION_UPLOAD,
            idaapi.SETMENU_APP
        )
        if not result:
            RuntimeError("Failed to attach upload action")

        logger.info("Installed the 'Upload to server' menu entry")

    def _uninstall_upload_action(self):
        result = idaapi.detach_action_from_menu(
            'File/Save...',
            self.ACTION_UPLOAD
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_UPLOAD)
        if not result:
            return False

        idaapi.free_custom_icon(self._icon_id_upload)
        self._icon_id_upload = idaapi.BADADDR

        logger.info("Uninstalled the 'Upload to server' menu entry")

    def _print_banner(self):
        params = PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_AUTHORS
        banner = "%s v%s - (c) %s" % params

        log("")
        log("-" * 75)
        log(banner)
        log("-" * 75)
        log("")
