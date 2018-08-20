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
import ctypes
import logging
import shutil
import tempfile
import os
import sys
from functools import partial

import ida_diskio
import ida_idaapi
import ida_loader
import ida_kernwin

from PyQt5.QtCore import Qt, QCoreApplication, QFileInfo
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QProgressDialog, QMessageBox

from ..utilities.misc import local_resource
from ..shared.commands import DownloadDatabase, UploadDatabase, Subscribe
from .dialogs import OpenDialog, SaveDialog

logger = logging.getLogger('IDArling.Interface')


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

        self._iconId = ida_idaapi.BADADDR

    def install(self):
        """
        Install the action into the IDA UI.

        :return: did the install succeed
        """
        # Read and load the icon file
        iconData = str(open(self._icon, 'rb').read())
        self._iconId = ida_kernwin.load_custom_icon(data=iconData)

        # Create the action description
        actionDesc = ida_kernwin.action_desc_t(self._ACTION_ID, self._text,
                                               self._handler, None,
                                               self._tooltip, self._iconId)

        # Register the action using its description
        result = ida_kernwin.register_action(actionDesc)
        if not result:
            raise RuntimeError("Failed to register action")

        # Attach the action to the chosen menu
        result = ida_kernwin.attach_action_to_menu(self._menu, self._ACTION_ID,
                                                   ida_kernwin.SETMENU_APP)
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
        result = ida_kernwin.detach_action_from_menu(self._menu,
                                                     self._ACTION_ID)
        if not result:
            return False

        # Un-register the action using its id
        result = ida_kernwin.unregister_action(self._ACTION_ID)
        if not result:
            return False

        # Free the custom icon using its id
        ida_kernwin.free_custom_icon(self._iconId)
        self._iconId = ida_idaapi.BADADDR

        logger.debug("Uninstalled the action")
        return True

    def update(self):
        """
        Force to update the action's state (enabled/disabled).
        """
        ida_kernwin.update_action_state(self._ACTION_ID,
                                        self._handler.update(None))


class ActionHandler(ida_kernwin.action_handler_t):
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
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE

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
    _ACTION_ID = 'idarling:open'

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
        progress.close()

        # Get the absolute path of the file
        appPath = QCoreApplication.applicationFilePath()
        appName = QFileInfo(appPath).fileName()
        fileExt = 'i64' if '64' in appName else 'idb'
        fileName = '%s_%s.%s' % (branch.repo, branch.name, fileExt)
        filePath = local_resource('files', fileName)

        # Write the packet content to disk
        with open(filePath, 'wb') as outputFile:
            outputFile.write(reply.content)
        logger.info("Saved file %s" % fileName)

        # Save the old database
        database = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if database:
            ida_loader.save_database(database, ida_loader.DBFL_TEMP)

        # Get the dynamic library
        idaname = 'ida64' if '64' in appName else 'ida'
        if sys.platform == 'win32':
            dllname, dlltype = idaname + '.dll', ctypes.windll
        elif sys.platform == 'linux2':
            dllname, dlltype = 'lib' + idaname + '.so', ctypes.cdll
        elif sys.platform == 'darwin':
            dllname, dlltype = 'lib' + idaname + '.dylib', ctypes.cdll
        dllpath = ida_diskio.idadir(None)
        if not os.path.exists(os.path.join(dllpath, dllname)):
            dllpath = dllpath.replace('ida64', 'ida')
        dll = dlltype[os.path.join(dllpath, dllname)]

        # Close the old database
        oldPath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if oldPath:
            dll.term_database()

        # Open the new database
        LP_c_char = ctypes.POINTER(ctypes.c_char)

        args = [appName, filePath]
        argc = len(args)
        argv = (LP_c_char * (argc + 1))()
        for i, arg in enumerate(args):
            arg = arg.encode('utf-8')
            argv[i] = ctypes.create_string_buffer(arg)

        LP_c_int = ctypes.POINTER(ctypes.c_int)
        v = ctypes.c_int(0)
        av = ctypes.addressof(v)
        pv = ctypes.cast(av, LP_c_int)
        dll.init_database(argc, argv, pv)

        # Create a copy of the new database
        fileExt = '.i64' if '64' in appName else '.idb'
        tmpFile, tmpPath = tempfile.mkstemp(suffix=fileExt)
        shutil.copyfile(filePath, tmpPath)

        class UIHooks(ida_kernwin.UI_Hooks):
            def database_inited(self, is_new_database, idc_script):
                self.unhook()

                # Remove the tmp database
                os.close(tmpFile)
                if os.path.exists(tmpPath):
                    os.remove(tmpPath)

        hooks = UIHooks()
        hooks.hook()

        # Open the tmp database
        s = ida_loader.snapshot_t()
        s.filename = tmpPath
        ida_kernwin.restore_database_snapshot(s, None, None)


class SaveAction(Action):
    """
    The "Save to server..." action installed in the "File" menu.
    """
    _ACTION_ID = 'idarling:save'

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
        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            return ida_kernwin.AST_DISABLE
        return super(SaveActionHandler, self).update(ctx)

    def _dialog_accepted(self, dialog):
        repo, branch = dialog.get_result()
        self._plugin.core.repo = repo.name
        self._plugin.core.branch = branch.name

        # Save the current database
        self._plugin.core.save_netnode()
        inputPath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        ida_loader.save_database(inputPath, ida_loader.DBFL_KILL)

        # Create the packet that will hold the database
        packet = UploadDatabase.Query(repo.name, branch.name)
        with open(inputPath, 'rb') as inputFile:
            packet.content = inputFile.read()

        # Create the progress dialog
        text = "Uploading database to server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, 1)
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        windowFlags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(windowFlags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Save to server")
        iconPath = self._plugin.resource('upload.png')
        progress.setWindowIcon(QIcon(iconPath))

        # Send the packet to upload the file
        packet.upback = partial(self._on_progress, progress)
        d = self._plugin.network.send_packet(packet)
        d.add_callback(partial(self._database_uploaded,
                               repo, branch, progress))
        d.add_errback(logger.exception)
        progress.show()

    def _database_uploaded(self, repo, branch, progress, _):
        # Close the progress dialog
        progress.close()

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
        color = self._plugin.interface.painter.color
        self._plugin.network.send_packet(Subscribe(repo.name, branch.name,
                                                   self._plugin.core.tick,
                                                   color))
        self._plugin.core.hook_all()
