import uuid
import datetime
import logging

import idc
import idaapi
import idautils
import ida_kernwin

from dialogs import OpenDialog, SaveDialog
from ..shared.models import Database, Revision
from ..shared.packets import (
    GetDatabases, GetRevisions, NewDatabase, NewRevision)


logger = logging.getLogger('IDAConnect.Interface')

# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------


class Action(object):
    _ACTION_ID = None

    def __init__(self, menu, text, tooltip, icon, handler):
        super(Action, self).__init__()
        self._menu = menu
        self._text = text
        self._tooltip = tooltip
        self._icon = icon
        self._handler = handler

        # Variables intialization
        self._iconId = idaapi.BADADDR

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def install(self):
        # Load the custom icon
        iconData = str(open(self._icon, 'rb').read())
        self._iconId = idaapi.load_custom_icon(data=iconData)

        # Create action description
        actionDesc = idaapi.action_desc_t(
            self._ACTION_ID,
            self._text,
            self._handler,
            None,
            self._tooltip,
            self._iconId)

        # Register the action
        result = idaapi.register_action(actionDesc)
        if not result:
            raise RuntimeError("Failed to register action")

        # Attach the action to menu
        result = idaapi.attach_action_to_menu(
            self._menu,
            self._ACTION_ID,
            idaapi.SETMENU_APP)
        if not result:
            raise RuntimeError("Failed to attach action")

        logger.info("Installed the action")

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def uninstall(self):
        # Detach the action from menu
        result = idaapi.detach_action_from_menu(
            self._menu,
            self._ACTION_ID)
        if not result:
            return False

        # Unregister the action
        result = idaapi.unregister_action(self._ACTION_ID)
        if not result:
            return False

        # Free the custom icon
        idaapi.free_custom_icon(self._iconId)
        self._iconId = idaapi.BADADDR

        logger.info("Uninstalled the action")
        return True

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def update(self):
        ida_kernwin.update_action_state(self._ACTION_ID,
                                        self._handler.update(None))


class ActionHandler(idaapi.action_handler_t):

    def __init__(self, plugin):
        super(ActionHandler, self).__init__()
        self._plugin = plugin

    def update(self, ctx):
        if self._plugin.getNetwork().isConnected():
            return idaapi.AST_ENABLE
        return idaapi.AST_DISABLE


class OpenAction(Action):
    _ACTION_ID = 'idaconnect:open'

    def __init__(self, plugin):
        super(OpenAction, self).__init__(
            'File/Open',
            'Open from server...',
            'Load a database from server',
            plugin.getResource('open.png'),
            OpenActionHandler(plugin))


class OpenActionHandler(ActionHandler):

    def activate(self, ctx):
        def onGetDatabasesReply(reply):
            dbs = reply['dbs']

            def onGetRevisionsReply(reply):
                revs = reply['revs']

                # Open the dialog
                dialog = OpenDialog(self._plugin, dbs, revs)

                # Catch acceptation
                def dialogAccepted():
                    db, rev = dialog.getResult()
                    # FIXME: Download the file

                dialog.accepted.connect(dialogAccepted)
                dialog.exec_()

            # Ask the server for the list of revs
            d = self._plugin.getNetwork().sendPacket(GetRevisions())
            d.addCallback(onGetRevisionsReply)
            d.addErrback(logger.exception)

        # Ask the server for the list of dbs
        d = self._plugin.getNetwork().sendPacket(GetDatabases())
        d.addCallback(onGetDatabasesReply)
        d.addErrback(logger.exception)
        return 1


class SaveAction(Action):
    _ACTION_ID = 'idaconnect:save'

    def __init__(self, plugin):
        super(SaveAction, self).__init__(
            'File/Save',
            'Save to server...',
            'Save a database to server',
            plugin.getResource('save.png'),
            SaveActionHandler(plugin))


class SaveActionHandler(ActionHandler):

    def activate(self, ctx):
        def onGetDatabasesReply(reply):
            dbs = reply['dbs']

            def onGetRevisionsReply(reply):
                revs = reply['revs']

                # Open the dialog
                dialog = SaveDialog(self._plugin, dbs, revs)

                # Catch acceptation
                def dialogAccepted():
                    db, rev = dialog.getResult()
                    if not db:
                        hash = idautils.GetInputFileMD5()
                        file = idc.GetInputFile()
                        type = idaapi.get_file_type_name()
                        dateFormat = "%Y/%m/%d %H:%M"
                        date = datetime.datetime.now().strftime(dateFormat)
                        db = Database(hash, file, type, date)
                        self._plugin.getNetwork().sendPacket(NewDatabase(db))

                    if not rev:
                        uuid_ = str(uuid.uuid4())
                        dateFormat = "%Y/%m/%d %H:%M"
                        date = datetime.datetime.now().strftime(dateFormat)
                        rev = Revision(db.getHash(), uuid_, date)
                        self._plugin.getNetwork().sendPacket(NewRevision(rev))

                    # FIXME: Upload the file

                dialog.accepted.connect(dialogAccepted)
                dialog.exec_()

            # Ask the server for the list of revs
            d = self._plugin.getNetwork().sendPacket(GetRevisions())
            d.addCallback(onGetRevisionsReply)
            d.addErrback(logger.exception)

        # Ask the server for the list of dbs
        d = self._plugin.getNetwork().sendPacket(GetDatabases())
        d.addCallback(onGetDatabasesReply)
        d.addErrback(logger.exception)
        return 1
