import os
import uuid
import datetime
import logging
from functools import partial

import idc
import idaapi
import idautils
import ida_loader
import ida_kernwin

from PyQt5.QtCore import Qt, QProcess
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import qApp, QProgressDialog, QMessageBox

from dialogs import OpenDialog, SaveDialog
from ..shared.commands import (
    GetDatabases, GetRevisions,
    NewDatabase, NewRevision,
    UploadFile, DownloadFile)
from ..shared.models import Database, Revision


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

        logger.debug("Installed the action")

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

        logger.debug("Uninstalled the action")
        return True

    # -------------------------------------------------------------------------
    # Actions
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
            plugin.getResource('download.png'),
            OpenActionHandler(plugin))


class OpenActionHandler(ActionHandler):

    def activate(self, ctx):
        # Ask the server for the list of dbs
        d = self._plugin.getNetwork().sendPacket(GetDatabases())
        d.addCallback(self._onGetDatabasesReply)
        d.addErrback(logger.exception)
        return 1

    def _onGetDatabasesReply(self, reply):
        # Ask the server for the list of revs
        d = self._plugin.getNetwork().sendPacket(GetRevisions())
        d.addCallback(partial(self._onGetRevisionsReply, reply.dbs))
        d.addErrback(logger.exception)

    def _onGetRevisionsReply(self, dbs, reply):
        # Open the open dialog
        dialog = OpenDialog(self._plugin, dbs, reply.revs)
        # Catch acceptation
        dialog.accepted.connect(partial(self._dialogAccepted, dialog))
        dialog.exec_()

    def _dialogAccepted(self, dialog):
        db, rev = dialog.getResult()

        # Create progress dialog
        text = "Download database from server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, 1)
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        windowFlags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(windowFlags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Open from server")
        iconPath = self._plugin.getResource('download.png')
        progress.setWindowIcon(QIcon(iconPath))

        # Sent packet and show progress
        packet = DownloadFile(db.getHash(), rev.getUUID())
        d = self._plugin.getNetwork().sendPacket(packet)
        callback = partial(self._progressCallback, progress)
        d.addInitback(lambda reply: reply.addDownback(callback))
        d.addCallback(partial(self._fileDownloaded, db, rev, progress))
        d.addErrback(logger.exception)
        progress.show()

    def _fileDownloaded(self, db, rev, progress, reply):
        # Close progress dialog
        self._progressCallback(progress, 1, 1)

        # FIXME: Make utility for accessing user directory
        filesDir = os.path.join(idaapi.get_user_idadir(),
                                '.idaconnect', 'files')
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        fileName = rev.getUUID() + ('.i64' if rev.getBits() else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Write the file to disk
        with open(filePath, 'wb') as file:
            file.write(reply.getContent())
        logger.info("Saved file %s" % fileName)

        # Show success dialog
        # success = QMessageBox()
        # success.setIcon(QMessageBox.Information)
        # success.setStandardButtons(QMessageBox.Ok)
        # success.setText("Database successfully downloaded!")
        # success.setWindowTitle("Open from server")
        # iconPath = self._plugin.getResource('download.png')
        # success.setWindowIcon(QIcon(iconPath))
        # success.exec_()

        # Save old and open new database
        idbPath = idc.GetIdbPath()
        if idbPath:
            idc.save_database(idbPath, ida_loader.DBFL_KILL)
        QProcess.startDetached(qApp.applicationFilePath(), [filePath])
        qApp.quit()  # FIXME: Is there a better way?

    def _progressCallback(self, progress, count, total):
        progress.setRange(0, total)  # Update range
        progress.setValue(count)  # Update progress bar


class SaveAction(Action):
    _ACTION_ID = 'idaconnect:save'

    def __init__(self, plugin):
        super(SaveAction, self).__init__(
            'File/Save',
            'Save to server...',
            'Save a database to server',
            plugin.getResource('upload.png'),
            SaveActionHandler(plugin))


class SaveActionHandler(ActionHandler):

    def update(self, ctx):
        if not idc.GetIdbPath():
            return idaapi.AST_DISABLE
        return super(SaveActionHandler, self).update(ctx)

    def activate(self, ctx):
        # Ask the server for the list of dbs
        d = self._plugin.getNetwork().sendPacket(GetDatabases())
        d.addCallback(self._onGetDatabasesReply)
        d.addErrback(logger.exception)
        return 1

    def _onGetDatabasesReply(self, reply):
        # Ask the server for the list of revs
        d = self._plugin.getNetwork().sendPacket(GetRevisions())
        d.addCallback(partial(self._onGetRevisionsReply, reply.dbs))
        d.addErrback(logger.exception)

    def _onGetRevisionsReply(self, dbs, reply):
        # Open the save dialog
        dialog = SaveDialog(self._plugin, dbs, reply.revs)
        # Catch acceptation
        dialog.accepted.connect(partial(self._dialogAccepted, dialog))
        dialog.exec_()

    def _dialogAccepted(self, dialog):
        db, rev = dialog.getResult()

        # Create new db if necessary
        if not db:
            hash = idautils.GetInputFileMD5()
            file = idc.GetInputFile()
            type = idaapi.get_file_type_name()
            dateFormat = "%Y/%m/%d %H:%M"
            date = datetime.datetime.now().strftime(dateFormat)
            db = Database(hash, file, type, date)
            self._plugin.getNetwork().sendPacket(NewDatabase(db))

        # Create new rev if ncessarry
        if not rev:
            uuid_ = str(uuid.uuid4())
            dateFormat = "%Y/%m/%d %H:%M"
            date = datetime.datetime.now().strftime(dateFormat)
            rev = Revision(db.getHash(), uuid_, date, idc.__EA64__)
            self._plugin.getNetwork().sendPacket(NewRevision(rev))

        # Create the packet holding the file
        packet = UploadFile(db.getHash(), rev.getUUID())
        inputPath = idc.GetIdbPath()
        with open(inputPath, 'rb') as inputFile:
            packet.setContent(inputFile.read())

        # Create the progress dialog
        text = "Uploading database to server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, len(packet.getContent()))
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        windowFlags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(windowFlags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Save to server")
        iconPath = self._plugin.getResource('upload.png')
        progress.setWindowIcon(QIcon(iconPath))

        # Send packet and show dialog
        packet.addUpback(partial(self._progressCallback, progress))
        self._plugin.getNetwork().sendPacket(packet)
        progress.show()

        # Show success dialog
        success = QMessageBox()
        success.setIcon(QMessageBox.Information)
        success.setStandardButtons(QMessageBox.Ok)
        success.setText("Database successfully uploaded!")
        success.setWindowTitle("Save to server")
        iconPath = self._plugin.getResource('upload.png')
        success.setWindowIcon(QIcon(iconPath))
        success.exec_()

    def _progressCallback(self, progress, count, total):
        progress.setRange(0, total)  # Update range
        progress.setValue(count)  # Update progress bar
