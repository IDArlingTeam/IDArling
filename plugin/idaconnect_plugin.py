import logging

import idaapi
import ida_kernwin

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

from idaconnect.hooks import HooksCore
from idaconnect.network import Network
from idaconnect.ui.dialogs import OpenDialog, SaveDialog
from idaconnect.ui.widgets import StatusWidget
from idaconnect.util import *

if not loggingStarted():
    logger = startLogging()


def PLUGIN_ENTRY():
    return IDAConnect()


class IDAConnect(idaapi.plugin_t):
    PLUGIN_NAME = "IDAConnect"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "The IDAConnect Team"

    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        self.hooks = HooksCore(self)
        self.network = Network(self)

        self._window = None
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                self._window = widget
        self._labelWidget = None
        self._statusWidget = None

    def init(self):
        try:
            self._init()
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        self._printBanner()
        logger.info("Successfully initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.warning("IDAConnect cannot be run as a script")

    def term(self):
        try:
            self._term()
        except Exception as e:
            logger.exception("Failed to terminate properly")

        logger.info("Terminated properly")

    def _init(self):
        self._installUI()
        self.hooks.install()
        self.network.install()

    def _term(self):
        self._uninstallUI()
        self.hooks.uninstall()
        self.network.uninstall()

    def _installUI(self):
        self._installOpenAction()
        self._installSaveAction()
        self._installWidgets()

    def _uninstallUI(self):
        self._uninstallOpenAction()
        self._uninstallSaveAction()
        self._uninstallWidgets()

    def _installWidgets(self):
        if self._statusWidget:
            return
        self._labelWidget = QLabel("%s v%s " % (self.PLUGIN_NAME,
                                                self.PLUGIN_VERSION))
        self._window.statusBar().addPermanentWidget(self._labelWidget)
        self._statusWidget = StatusWidget(self)
        self._window.statusBar().addPermanentWidget(self._statusWidget)
        logger.info("Installed widgets in status bar")

    def _uninstallWidgets(self):
        if not self._statusWidget:
            return
        self._window.statusBar().removeWidget(self._labelWidget)
        self._window.statusBar().removeWidget(self._statusWidget)
        logger.info("Uninstalled widgets from status bar")

    ACTION_OPEN = 'idaconnect:open'
    ACTION_SAVE = 'idaconnect:save'

    def _installOpenAction(self):
        plugin = self

        class OpenActionHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                dialog = OpenDialog(plugin, [])

                def dialogAccepted():
                    db, rev = dialog.getResult()
                    print 'Opening from database %s' % db.getName()
                    print 'and from revision %s' % rev.getName()
                dialog.accepted.connect(dialogAccepted)
                dialog.exec_()
                return 1

            def update(self, ctx):
                if plugin.network.isConnected():
                    return idaapi.AST_ENABLE
                return idaapi.AST_DISABLE

        iconPath = pluginResource('open.png')
        iconData = str(open(iconPath, 'rb').read())
        self._openIconId = idaapi.load_custom_icon(data=iconData)

        self._openHandler = OpenActionHandler()
        actionDesc = idaapi.action_desc_t(
            self.ACTION_OPEN,
            "Open from server...",
            self._openHandler,
            None,
            "Load a database from the server",
            self._openIconId
        )

        result = idaapi.register_action(actionDesc)
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

    def _uninstallOpenAction(self):
        result = idaapi.detach_action_from_menu(
            'File/Open...',
            self.ACTION_OPEN
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_OPEN)
        if not result:
            return False

        idaapi.free_custom_icon(self._openIconId)
        self._openIconId = idaapi.BADADDR

        logger.info("Uninstalled the 'Open from server' menu entry")

    def _updateOpenAction(self):
        ida_kernwin.update_action_state(self.ACTION_OPEN,
                                        self._openHandler.update(None))

    def _installSaveAction(self):
        plugin = self

        class SaveActionHandler(idaapi.action_handler_t):

            def activate(self, ctx):
                dialog = SaveDialog(plugin, [])

                def dialogAccepted():
                    db, rev = dialog.getResult()
                    print 'Saving to database %s' % db.getName()
                    print 'and to revision %s' % rev.getName()
                dialog.accepted.connect(dialogAccepted)
                dialog.exec_()
                return 1

            def update(self, ctx):
                if plugin.network.isConnected():
                    return idaapi.AST_ENABLE
                return idaapi.AST_DISABLE

        iconPath = pluginResource('save.png')
        iconData = str(open(iconPath, 'rb').read())
        self._saveIconId = idaapi.load_custom_icon(data=iconData)

        self._saveHandler = SaveActionHandler()
        actionDesc = idaapi.action_desc_t(
            self.ACTION_SAVE,
            "Save to server...",
            self._saveHandler,
            None,
            "Save the database to the server",
            self._saveIconId
        )

        result = idaapi.register_action(actionDesc)
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

    def _uninstallSaveAction(self):
        result = idaapi.detach_action_from_menu(
            'File/Save...',
            self.ACTION_SAVE
        )
        if not result:
            return False

        result = idaapi.unregister_action(self.ACTION_SAVE)
        if not result:
            return False

        idaapi.free_custom_icon(self._saveIconId)
        self._saveIconId = idaapi.BADADDR

        logger.info("Uninstalled the 'Save to server' menu entry")

    def _updateSaveAction(self):
        ida_kernwin.update_action_state(self.ACTION_SAVE,
                                        self._saveHandler.update(None))

    def _updateActions(self):
        self._updateOpenAction()
        self._updateSaveAction()

    def _printBanner(self):
        parameters = self.PLUGIN_NAME, self.PLUGIN_VERSION, self.PLUGIN_AUTHORS
        bannerText = "%s v%s - (c) %s" % parameters

        prefix = '[IDAConnect] '
        print prefix + ("-" * 75)
        print prefix + bannerText
        print prefix + ("-" * 75)

    def getResource(self, resource):
        return pluginResource(resource)

    def whenDisconnected(self):
        self._statusWidget.setState(StatusWidget.DISCONNECTED)
        self._statusWidget.setServer()
        self._updateActions()

    def whenConnecting(self):
        self._statusWidget.setState(StatusWidget.CONNECTING)
        self._statusWidget.setServer(self.network.getHost())
        self._updateActions()

    def whenConnected(self):
        self._statusWidget.setState(StatusWidget.CONNECTED)
        self._updateActions()
