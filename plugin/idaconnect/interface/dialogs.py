# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import logging
from collections import namedtuple
from functools import partial

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QDialog, QHBoxLayout, QVBoxLayout,
                             QGridLayout, QWidget, QTableWidget,
                             QTableWidgetItem, QGroupBox, QLabel, QPushButton,
                             QLineEdit)

from ..shared.models import Repository

logger = logging.getLogger('IDAConnect.Interface')


class OpenDialog(QDialog):
    """
    The open dialog allowing an user to select a remote database to download.
    """

    def __init__(self, plugin, repos, branches):
        """
        Initialize the open dialog.

        :param plugin: the plugin instance
        :param repos: the list of repositories
        :param branches: the list of branches
        """
        super(OpenDialog, self).__init__()
        self._plugin = plugin
        self._repos = repos
        self._branches = branches

        # General setup of the dialog
        logger.debug("Showing open database dialog")
        self.setWindowTitle("Open from Remote Server")
        iconPath = self._plugin.resource('download.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(900, 450)

        # Setup of the layout and widgets
        layout = QHBoxLayout(self)
        self._reposTable = QTableWidget(len(repos), 1, self)
        self._reposTable.setHorizontalHeaderLabels(('Remote Repositories',))
        for i, repo in enumerate(repos):
            item = QTableWidgetItem("%s (%s)" % (str(repo.file),
                                                 str(repo.hash)))
            item.setData(Qt.UserRole, repo)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._reposTable.setItem(i, 0, item)
        self._reposTable.horizontalHeader().setSectionsClickable(False)
        self._reposTable.horizontalHeader().setStretchLastSection(True)
        self._reposTable.verticalHeader().setVisible(False)
        self._reposTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._reposTable.setSelectionMode(QTableWidget.SingleSelection)
        self._reposTable.itemClicked.connect(self._repoClicked)
        minSZ = self._reposTable.minimumSize()
        self._reposTable.setMinimumSize(300, minSZ.height())
        maxSZ = self._reposTable.maximumSize()
        self._reposTable.setMaximumSize(300, maxSZ.height())
        layout.addWidget(self._reposTable)

        rightSide = QWidget(self)
        rightLayout = QVBoxLayout(rightSide)
        infoGroup = QGroupBox("Information", rightSide)
        infoLayout = QGridLayout(infoGroup)
        self._fileLabel = QLabel('<b>File:</b>')
        infoLayout.addWidget(self._fileLabel, 0, 0)
        self._hashLabel = QLabel('<b>Hash:</b>')
        infoLayout.addWidget(self._hashLabel, 1, 0)
        infoLayout.setColumnStretch(0, 1)
        self._typeLabel = QLabel('<b>Type:</b>')
        infoLayout.addWidget(self._typeLabel, 0, 1)
        self._dateLabel = QLabel('<b>Date:</b>')
        infoLayout.addWidget(self._dateLabel, 1, 1)
        infoLayout.setColumnStretch(1, 1)
        rightLayout.addWidget(infoGroup)

        branchesGroup = QGroupBox("Branches", rightSide)
        branchesLayout = QGridLayout(branchesGroup)
        self._branchesTable = QTableWidget(0, 2, branchesGroup)
        self._branchesTable.setHorizontalHeaderLabels(('Identifier', 'Date'))
        horizontalHeader = self._branchesTable.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)
        horizontalHeader.setSectionResizeMode(0, horizontalHeader.Stretch)
        self._branchesTable.verticalHeader().setVisible(False)
        self._branchesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._branchesTable.setSelectionMode(QTableWidget.SingleSelection)
        self._branchesTable.itemClicked.connect(self._branchClicked)
        branchesLayout.addWidget(self._branchesTable, 0, 0)
        rightLayout.addWidget(branchesGroup)

        buttonsWidget = QWidget(rightSide)
        buttonsLayout = QHBoxLayout(buttonsWidget)
        buttonsLayout.addStretch()
        self._openButton = QPushButton("Open")
        self._openButton.setEnabled(False)
        self._openButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(self._openButton)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(cancelButton)
        rightLayout.addWidget(buttonsWidget)
        layout.addWidget(rightSide)

    def _repoClicked(self, item):
        """
        Called when a repository item is clicked, will update the display.

        :param item: the item clicked
        """
        repo = item.data(Qt.UserRole)
        self._fileLabel.setText('<b>File:</b> %s' % str(repo.file))
        self._hashLabel.setText('<b>Hash:</b> %s' % str(repo.hash))
        self._typeLabel.setText('<b>Type:</b> %s' % str(repo.type))
        self._dateLabel.setText('<b>Date:</b> %s' % str(repo.date))

        # Display the list of branches for the selected repository
        branches = [br for br in self._branches if br.hash == repo.hash]
        self._branchesTable.setRowCount(len(branches))
        for i, branch in enumerate(branches):
            item = QTableWidgetItem(str(branch.uuid))
            item.setData(Qt.UserRole, branch)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._branchesTable.setItem(i, 0, item)
            item = QTableWidgetItem(str(branch.date))
            item.setData(Qt.UserRole, branch)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._branchesTable.setItem(i, 1, item)

    def _branchClicked(self, _):
        """
        Called when a branch item is clicked.
        """
        self._openButton.setEnabled(True)

    def getResult(self):
        """
        Get the result (repository, branch) from this dialog.

        :return: the result
        """
        repo = self._reposTable.currentItem().data(Qt.UserRole)
        return repo, self._branchesTable.currentItem().data(Qt.UserRole)


class SaveDialog(QDialog):
    """
    The save dialog allowing an user to select a remote database to upload to.
    """

    def __init__(self, plugin, repos, branches):
        """
        Initialize the save dialog.

        :param plugin: the plugin instance
        :param repos: the list of repositories
        :param branches: the list of branches
        """
        super(SaveDialog, self).__init__()
        self._plugin = plugin
        self._repos = repos
        self._branches = branches

        # General setup of the dialog
        logger.debug("Showing save database dialog")
        self.setWindowTitle("Save to Remote Server")
        iconPath = self._plugin.resource('upload.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(900, 450)

        # Setup the layout and widgets
        layout = QHBoxLayout(self)
        self._reposTable = QTableWidget(len(repos) + 1, 1, self)
        self._reposTable.setHorizontalHeaderLabels(('Remote Repositories',))
        for i, repo in enumerate(repos):
            item = QTableWidgetItem("%s (%s)" % (str(repo.file),
                                                 str(repo.hash)))
            item.setData(Qt.UserRole, repo)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._reposTable.setItem(i, 0, item)
        newItem = QTableWidgetItem("<new repository>")
        newItem.setData(Qt.UserRole, None)
        newItem.setFlags(newItem.flags() & ~Qt.ItemIsEditable)
        self._reposTable.setItem(len(repos), 0, newItem)
        self._reposTable.horizontalHeader().setSectionsClickable(False)
        self._reposTable.horizontalHeader().setStretchLastSection(True)
        self._reposTable.verticalHeader().setVisible(False)
        self._reposTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._reposTable.setSelectionMode(QTableWidget.SingleSelection)
        self._reposTable.itemClicked.connect(self._repoClicked)
        minSZ = self._reposTable.minimumSize()
        self._reposTable.setMinimumSize(300, minSZ.height())
        maxSZ = self._reposTable.maximumSize()
        self._reposTable.setMaximumSize(300, maxSZ.height())
        layout.addWidget(self._reposTable)

        rightSide = QWidget(self)
        rightLayout = QVBoxLayout(rightSide)
        infoGroup = QGroupBox("Information", rightSide)
        infoLayout = QGridLayout(infoGroup)
        self._fileLabel = QLabel('<b>File:</b>')
        infoLayout.addWidget(self._fileLabel, 0, 0)
        self._hashLabel = QLabel('<b>Hash:</b>')
        infoLayout.addWidget(self._hashLabel, 1, 0)
        infoLayout.setColumnStretch(0, 1)
        self._typeLabel = QLabel('<b>Type:</b>')
        infoLayout.addWidget(self._typeLabel, 0, 1)
        self._dateLabel = QLabel('<b>Date:</b>')
        infoLayout.addWidget(self._dateLabel, 1, 1)
        infoLayout.setColumnStretch(1, 1)
        rightLayout.addWidget(infoGroup)

        branchesGroup = QGroupBox("Branches", rightSide)
        branchesLayout = QGridLayout(branchesGroup)
        self._branchesTable = QTableWidget(0, 2, branchesGroup)
        self._branchesTable.setHorizontalHeaderLabels(('Identifier', 'Date'))
        horizontalHeader = self._branchesTable.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)
        horizontalHeader.setSectionResizeMode(0, horizontalHeader.Stretch)
        self._branchesTable.verticalHeader().setVisible(False)
        self._branchesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._branchesTable.setSelectionMode(QTableWidget.SingleSelection)
        branchesLayout.addWidget(self._branchesTable, 0, 0)
        rightLayout.addWidget(branchesGroup)

        buttonsWidget = QWidget(rightSide)
        buttonsLayout = QHBoxLayout(buttonsWidget)
        buttonsLayout.addStretch()
        self._saveButton = QPushButton("Save")
        self._saveButton.setEnabled(False)
        self._saveButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(self._saveButton)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(cancelButton)
        rightLayout.addWidget(buttonsWidget)
        layout.addWidget(rightSide)

    def _repoClicked(self, item):
        """
        Called when a repository item is clicked, will update the display.

        :param item: the item clicked
        """
        repo = item.data(Qt.UserRole)
        repo = repo if repo else Repository('', '', '', '')
        self._saveButton.setEnabled(True)
        self._fileLabel.setText('<b>File:</b> %s' % str(repo.file))
        self._hashLabel.setText('<b>Hash:</b> %s' % str(repo.hash))
        self._typeLabel.setText('<b>Type:</b> %s' % str(repo.type))
        self._dateLabel.setText('<b>Date:</b> %s' % str(repo.date))

        # Display the list of branches for the selected repository
        branches = [br for br in self._branches if br.hash == repo.hash]
        self._branchesTable.setRowCount(len(branches) + 1)
        for i, br in enumerate(branches):
            item = QTableWidgetItem(str(br.uuid))
            item.setData(Qt.UserRole, br)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._branchesTable.setItem(i, 0, item)
            item = QTableWidgetItem(str(br.date))
            item.setData(Qt.UserRole, br)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._branchesTable.setItem(i, 1, item)
        newItem = QTableWidgetItem("<new branch>")
        item.setData(Qt.UserRole, None)
        newItem.setFlags(newItem.flags() & ~Qt.ItemIsEditable)
        self._branchesTable.setItem(len(branches), 0, newItem)
        newItem = QTableWidgetItem()
        item.setData(Qt.UserRole, None)
        newItem.setFlags(newItem.flags() & ~Qt.ItemIsEditable)
        self._branchesTable.setItem(len(branches), 1, newItem)

    def _branchClicked(self, _):
        """
        Called when a branch item is clicked.
        """
        self._saveButton.setEnabled(True)

    def getResult(self):
        """
        Get the result (repository, branch) from this dialog.

        :return: the result
        """
        repo = self._reposTable.currentItem().data(Qt.UserRole)
        return repo, self._branchesTable.currentItem().data(Qt.UserRole)


class NetworkSettingsDialog(QDialog):
    """
    The network settings dialog allowing an user to select a remote server to
    connect to.
    """

    def __init__(self, plugin):
        """
        Initialize the network settings dialog.

        :param plugin: the plugin instance
        """
        super(NetworkSettingsDialog, self).__init__()
        self._plugin = plugin
        self._servers = self._plugin.core._servers

        # General setup of the dialog
        logger.debug("Showing network settings dialog")
        self.setWindowTitle("Network Settings")
        iconPath = self._plugin.resource('settings.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(300, 300)

        layout = QVBoxLayout(self)
        self._serversTable = QTableWidget(len(self._servers), 1, self)
        self._serversTable.setHorizontalHeaderLabels(('Server list',))
        for i, server in enumerate(self._servers):
            item = QTableWidgetItem("%s" % (str(server.host)))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._serversTable.setItem(i, 0, item)

        self._serversTable.horizontalHeader().setSectionsClickable(False)
        self._serversTable.horizontalHeader().setStretchLastSection(True)
        self._serversTable.verticalHeader().setVisible(False)
        self._serversTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._serversTable.setSelectionMode(QTableWidget.SingleSelection)
        self._serversTable.itemClicked.connect(self._serverClicked)
        minSZ = self._serversTable.minimumSize()
        self._serversTable.setMinimumSize(300, minSZ.height())
        maxSZ = self._serversTable.maximumSize()
        self._serversTable.setMaximumSize(300, maxSZ.height())
        layout.addWidget(self._serversTable)

        buttonsWidget = QWidget(self)
        buttonsLayout = QHBoxLayout(buttonsWidget)

        # Add server button
        self._addButton = QPushButton("Add Server")
        self._addButton.clicked.connect(self._addButtonClicked)
        buttonsLayout.addWidget(self._addButton)

        # Delete server button
        self._deleteButton = QPushButton("Delete Server")
        self._deleteButton.setEnabled(False)
        self._deleteButton.clicked.connect(self._deleteButtonClicked)
        buttonsLayout.addWidget(self._deleteButton)

        # Cancel button
        self._quitButton = QPushButton("Quit")
        self._quitButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(self._quitButton)

        buttonsLayout.addWidget(buttonsWidget)
        layout.addWidget(buttonsWidget)

    def _serverClicked(self, item):
        """
        Called when a server item is clicked.
        """
        self._itemClicked = item
        self._deleteButton.setEnabled(True)

    def _addButtonClicked(self, _):
        """
        Called when the add button is clicked.
        """
        dialog = AddServerDialog(self._plugin)
        dialog.accepted.connect(partial(self._dialogAccepted, dialog))
        dialog.exec_()

    def _dialogAccepted(self, dialog):
        """
        Called when the add server dialog is accepted by the user.

        :param dialog: the add server dialog
        """
        host, port = dialog.getResult()
        Server = namedtuple('Server', ['host', 'port'])
        server = Server(host, port)
        self._servers += [server]
        rowCount = self._serversTable.rowCount()
        self._serversTable.insertRow(rowCount)
        newServer = QTableWidgetItem(server.host)
        self._serversTable.setItem(rowCount, 0, newServer)
        self.update()

    def _deleteButtonClicked(self, _):
        """
        Called when the delete button is clicked.
        """
        self._servers.remove(self._itemClicked.data(Qt.UserRole))
        self._serversTable.removeRow(self._itemClicked.row())
        self.update()


class AddServerDialog(QDialog):
    """
    The add server dialog allowing an user to add a remote server to connect to.
    """

    def __init__(self, plugin):
        """
        Initialize the network setting dialog.

        :param plugin: the plugin instance
        """
        super(AddServerDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        logger.debug("Add server settings dialog")
        self.setWindowTitle("Add server")
        iconPath = self._plugin.resource('settings.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(100, 100)

        layout = QVBoxLayout(self)

        self._serverNameLabel = QLabel('<b>Server name or IP</b>')
        layout.addWidget(self._serverNameLabel)
        self._serverName = QLineEdit()
        self._serverName.setPlaceholderText('Server name or IP')
        layout.addWidget(self._serverName)

        self._serverNameLabel = QLabel('<b>Server port</b>')
        layout.addWidget(self._serverNameLabel)
        self._serverPort = QLineEdit()
        self._serverPort.setPlaceholderText('Server port')
        layout.addWidget(self._serverPort)

        downSide = QWidget(self)
        buttonsLayout = QHBoxLayout(downSide)
        self._addButton = QPushButton("Add")
        self._addButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(self._addButton)
        self._cancelButton = QPushButton("Cancel")
        self._cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(self._cancelButton)
        layout.addWidget(downSide)

    def getResult(self):
        """
        Get the result (server, port) from this dialog.

        :return: the result
        """
        return self._serverName.text(), self._serverPort.text()


