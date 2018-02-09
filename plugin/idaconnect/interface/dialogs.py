import logging

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QDialog, QHBoxLayout, QVBoxLayout,
                             QGridLayout, QWidget, QTableWidget,
                             QTableWidgetItem, QGroupBox, QLabel, QPushButton)

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
        Initialize the open dialog.

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
