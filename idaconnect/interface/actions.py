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
import logging
from functools import partial

import ida_loader
import ida_kernwin
import idaapi
import idc

from PyQt5.QtCore import Qt, QProcess
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import qApp, QProgressDialog, QMessageBox

from ..utilities.misc import local_resource
from ..shared.commands import DownloadDatabase, UploadDatabase, Subscribe
from .dialogs import OpenDialog, SaveDialog

logger = logging.getLogger('IDAConnect.Interface')


class Action(object):
    """
    This is a base class for all the actions of the interface module.
    """
    _ACTION_ID = None

    def __init__(self, menu, text, tooltip, icon, handler):
        """
        Initialize the action.

        :param menu: the menu to attach to
        :param text: the text to display
        :param tooltip: the tooltip to show
        :param icon: the path to the icon
        :param handler: the action handler
        """
        super(Action, self).__init__()
        self._menu = menu
        self._text = text
        self._tooltip = tooltip
        self._icon = icon
        self._handler = handler

        self._iconId = idaapi.BADADDR

    def install(self):
        """
        Install the action into the IDA UI.

        :return: did the install succeed
        """
        # Read and load the icon file
        iconData = str(open(self._icon, 'rb').read())
        self._iconId = idaapi.load_custom_icon(data=iconData)

        # Create the action description
        actionDesc = idaapi.action_desc_t(self._ACTION_ID, self._text,
                                          self._handler, None, self._tooltip,
                                          self._iconId)

        # Register the action using its description
        result = idaapi.register_action(actionDesc)
        if not result:
            raise RuntimeError("Failed to register action")

        # Attach the action to the chosen menu
        result = idaapi.attach_action_to_menu(self._menu, self._ACTION_ID,
                                              idaapi.SETMENU_APP)
        if not result:
            raise RuntimeError("Failed to attach action")

        logger.debug("Installed the action")
        return True

    def uninstall(self):
        """
        Uninstall the action from the IDA UI.

        :return: did the uninstall succeed
        """
        # Detach the action from the chosen menu
        result = idaapi.detach_action_from_menu(self._menu, self._ACTION_ID)
        if not result:
            return False

        # Un-register the action using its id
        result = idaapi.unregister_action(self._ACTION_ID)
        if not result:
            return False

        # Free the custom icon using its id
        idaapi.free_custom_icon(self._iconId)
        self._iconId = idaapi.BADADDR

        logger.debug("Uninstalled the action")
        return True

    def update(self):
        """
        Force to update the action's state (enabled/disabled).
        """
        ida_kernwin.update_action_state(self._ACTION_ID,
                                        self._handler.update(None))


class ActionHandler(idaapi.action_handler_t):
    """
    This is the base class for all action handlers of the interface module.
    """
    _DIALOG = None

    @staticmethod
    def _on_progress(progress, count, total):
        """
        Called when some data has been exchanged.

        :param progress: the progress dialog
        :param count: the number of bytes exchanged
        :param total: the total number of bytes to exchange
        """
        progress.setRange(0, total)
        progress.setValue(count)

    def __init__(self, plugin):
        """
        Initialize the action handler.

        :param plugin: the plugin instance
        """
        super(ActionHandler, self).__init__()
        self._plugin = plugin

    def update(self, ctx):
        """
        Update the state of the associated action.

        :param ctx: the context
        :return: should the action be enabled or not
        """
        if self._plugin.network.connected:
            return idaapi.AST_ENABLE
        return idaapi.AST_DISABLE

    def activate(self, ctx):
        """
        Called when the action is triggered.

        :param ctx: the context
        :return: refresh or not the IDA windows
        """
        # Ask the server for the list of repositories
        dialog = self._DIALOG(self._plugin)
        dialog.accepted.connect(partial(self._dialog_accepted, dialog))
        dialog.exec_()
        return 1

    def _dialog_accepted(self, dialog):
        """
        Called when the dialog is accepted by the user.

        :param dialog: the dialog
        """
        raise NotImplementedError("dialog_accepted() not implemented")


class OpenAction(Action):
    """
    The "Open from server..." action installed in the "File" menu.
    """
    _ACTION_ID = 'idaconnect:open'

    def __init__(self, plugin):
        super(OpenAction, self).__init__(
            'File/Open',
            'Open from server...',
            'Load a database from server',
            plugin.resource('download.png'),
            OpenActionHandler(plugin))


class OpenActionHandler(ActionHandler):
    """
    The action handler for the open action.
    """
    _DIALOG = OpenDialog

    def _dialog_accepted(self, dialog):
        repo, branch = dialog.get_result()

        # Create the progress dialog
        text = "Downloading database from server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, 1)
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        windowFlags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(windowFlags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Open from server")
        iconPath = self._plugin.resource('download.png')
        progress.setWindowIcon(QIcon(iconPath))

        # Send a packet to download the database
        packet = DownloadDatabase.Query(repo.name, branch.name)
        callback = partial(self._on_progress, progress)

        def setDownloadCallback(reply):
            reply.downback = callback

        d = self._plugin.network.send_packet(packet)
        d.add_initback(setDownloadCallback)
        d.add_callback(partial(self._database_downloaded, branch, progress))
        d.add_errback(logger.exception)
        progress.show()

    def _database_downloaded(self, branch, progress, reply):
        """
        Called when the file has been downloaded.

        :param branch: the branch
        :param progress: the progress dialog
        :param reply: the reply from the server
        """
        # Close the progress dialog
        self._on_progress(progress, 1, 1)

        # Get the absolute path of the file
        fileExt = 'i64' if idc.__EA64__ else 'idb'
        fileName = '%s_%s.%s' % (branch.repo, branch.name, fileExt)
        filePath = local_resource('files', fileName)

        # Write the packet content to disk
        with open(filePath, 'wb') as outputFile:
            outputFile.write(reply.content)
        logger.info("Saved file %s" % fileName)

        # Save the old database
        database = idc.GetIdbPath()
        if database:
            idc.save_database(database, ida_loader.DBFL_KILL)
        # Save the current state
        self._plugin.core.save_state(True, database)
        # Open the new database
        QProcess.startDetached(qApp.applicationFilePath(), [filePath])
        qApp.quit()  # https://forum.hex-rays.com/viewtopic.php?f=8&t=4294


class SaveAction(Action):
    """
    The "Save to server..." action installed in the "File" menu.
    """
    _ACTION_ID = 'idaconnect:save'

    def __init__(self, plugin):
        super(SaveAction, self).__init__(
            'File/Save',
            'Save to server...',
            'Save a database to server',
            plugin.resource('upload.png'),
            SaveActionHandler(plugin))


class SaveActionHandler(ActionHandler):
    """
    The action handler for the save action.
    """
    _DIALOG = SaveDialog

    def update(self, ctx):
        if not idc.GetIdbPath():
            return idaapi.AST_DISABLE
        return super(SaveActionHandler, self).update(ctx)

    def _dialog_accepted(self, dialog):
        repo, branch = dialog.get_result()
        self._plugin.core.repo = repo.name
        self._plugin.core.branch = branch.name

        # Save the current database
        self._plugin.core.save_netnode()
        idc.save_database(idc.GetIdbPath(), 0)

        # Create the packet that will hold the database
        packet = UploadDatabase.Query(repo.name, branch.name)
        inputPath = idc.GetIdbPath()
        with open(inputPath, 'rb') as inputFile:
            packet.content = inputFile.read()

        # Create the progress dialog
        text = "Uploading database to server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, len(packet.content))
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        windowFlags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(windowFlags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Save to server")
        iconPath = self._plugin.resource('upload.png')
        progress.setWindowIcon(QIcon(iconPath))
        progress.show()

        # Send the packet to upload the file
        packet.upback = partial(self._on_progress, progress)
        d = self._plugin.network.send_packet(packet)
        d.add_callback(partial(self._database_uploaded, repo, branch))
        d.add_errback(logger.exception)

    def _database_uploaded(self, repo, branch, _):
        # Show a success dialog
        success = QMessageBox()
        success.setIcon(QMessageBox.Information)
        success.setStandardButtons(QMessageBox.Ok)
        success.setText("Database successfully uploaded!")
        success.setWindowTitle("Save to server")
        iconPath = self._plugin.resource('upload.png')
        success.setWindowIcon(QIcon(iconPath))
        success.exec_()

        # Subscribe to the new events stream
        self._plugin.network.send_packet(Subscribe(repo.name, branch.name,
                                                   self._plugin.core.tick))
        self._plugin.core.hook_all()
