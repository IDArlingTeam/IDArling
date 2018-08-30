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
import datetime
import logging
from functools import partial

import ida_loader
import ida_nalt

from PyQt5.QtCore import Qt, QRegExp
from PyQt5.QtGui import QIcon, QRegExpValidator, QColor
from PyQt5.QtWidgets import (QDialog, QHBoxLayout, QVBoxLayout, QGridLayout,
                             QWidget, QTableWidget, QTableWidgetItem, QLabel,
                             QPushButton, QLineEdit, QGroupBox, QMessageBox,
                             QCheckBox, QTabWidget, QColorDialog, QComboBox,
                             QFormLayout, QSpinBox, QHeaderView)

from ..shared.commands import GetRepositories, GetBranches, \
    NewRepository, NewBranch, UserRenamed, UserColorChanged
from ..shared.models import Repository, Branch

logger = logging.getLogger('IDArling.Interface')


class OpenDialog(QDialog):
    """
    The open dialog allowing an user to select a remote database to download.
    """

    def __init__(self, plugin):
        """
        Initialize the open dialog.

        :param plugin: the plugin instance
        """
        super(OpenDialog, self).__init__()
        self._plugin = plugin
        self._repos = None
        self._branches = None

        # General setup of the dialog
        logger.debug("Showing the database selection dialog")
        self.setWindowTitle("Open from Remote Server")
        iconPath = self._plugin.resource('download.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(900, 450)

        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        mainLayout = QHBoxLayout(main)
        layout.addWidget(main)

        self._leftSide = QWidget(main)
        self._leftLayout = QVBoxLayout(self._leftSide)
        self._reposTable = QTableWidget(0, 1, self._leftSide)
        self._reposTable.setHorizontalHeaderLabels(('Repositories',))
        self._reposTable.horizontalHeader().setSectionsClickable(False)
        self._reposTable.horizontalHeader().setStretchLastSection(True)
        self._reposTable.verticalHeader().setVisible(False)
        self._reposTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._reposTable.setSelectionMode(QTableWidget.SingleSelection)
        self._reposTable.itemSelectionChanged.connect(self._repo_clicked)
        self._leftLayout.addWidget(self._reposTable)
        mainLayout.addWidget(self._leftSide)

        rightSide = QWidget(main)
        rightLayout = QVBoxLayout(rightSide)
        detailsGroup = QGroupBox("Details", rightSide)
        detailsLayout = QGridLayout(detailsGroup)
        self._fileLabel = QLabel('<b>File:</b>')
        detailsLayout.addWidget(self._fileLabel, 0, 0)
        self._hashLabel = QLabel('<b>Hash:</b>')
        detailsLayout.addWidget(self._hashLabel, 1, 0)
        detailsLayout.setColumnStretch(0, 1)
        self._typeLabel = QLabel('<b>Type:</b>')
        detailsLayout.addWidget(self._typeLabel, 0, 1)
        self._dateLabel = QLabel('<b>Date:</b>')
        detailsLayout.addWidget(self._dateLabel, 1, 1)
        detailsLayout.setColumnStretch(1, 1)
        rightLayout.addWidget(detailsGroup)
        mainLayout.addWidget(rightSide)

        self._branchesGroup = QGroupBox("Branches", rightSide)
        self._branchesLayout = QVBoxLayout(self._branchesGroup)
        self._branchesTable = QTableWidget(0, 3, self._branchesGroup)
        labels = ('Name', 'Date', 'Ticks')
        self._branchesTable.setHorizontalHeaderLabels(labels)
        horizontalHeader = self._branchesTable.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)
        horizontalHeader.setSectionResizeMode(0, horizontalHeader.Stretch)
        self._branchesTable.verticalHeader().setVisible(False)
        self._branchesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._branchesTable.setSelectionMode(QTableWidget.SingleSelection)
        self._branchesTable.itemSelectionChanged.connect(self._branch_clicked)
        branch_double_clicked = self._branch_double_clicked
        self._branchesTable.itemDoubleClicked.connect(branch_double_clicked)
        self._branchesLayout.addWidget(self._branchesTable)
        rightLayout.addWidget(self._branchesGroup)

        buttonsWidget = QWidget(self)
        buttonsLayout = QHBoxLayout(buttonsWidget)
        buttonsLayout.addStretch()
        self._acceptButton = QPushButton("Open", buttonsWidget)
        self._acceptButton.setEnabled(False)
        self._acceptButton.clicked.connect(self.accept)
        cancelButton = QPushButton("Cancel", buttonsWidget)
        cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(cancelButton)
        buttonsLayout.addWidget(self._acceptButton)
        layout.addWidget(buttonsWidget)

        # Ask the server for the list of repositories
        d = self._plugin.network.send_packet(GetRepositories.Query())
        d.add_callback(self._on_get_repos)
        d.add_errback(logger.exception)

    def _on_get_repos(self, reply):
        """
        Called when the list of repositories is received.

        :param reply: the reply from the server
        """
        self._repos = reply.repos
        self._refresh_repos()

    def _refresh_repos(self):
        """
        Refreshes the table of repositories.
        """
        self._reposTable.setRowCount(len(self._repos))
        for i, repo in enumerate(self._repos):
            item = QTableWidgetItem(repo.name)
            item.setData(Qt.UserRole, repo)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._reposTable.setItem(i, 0, item)

    def _repo_clicked(self):
        """
        Called when a repository item is clicked, will update the display.
        """
        repo = self._reposTable.selectedItems()[0].data(Qt.UserRole)
        self._fileLabel.setText('<b>File:</b> %s' % str(repo.file))
        self._hashLabel.setText('<b>Hash:</b> %s' % str(repo.hash))
        self._typeLabel.setText('<b>Type:</b> %s' % str(repo.type))
        self._dateLabel.setText('<b>Date:</b> %s' % str(repo.date))

        # Ask the server for the list of branches
        d = self._plugin.network.send_packet(GetBranches.Query(repo.name))
        d.add_callback(partial(self._on_get_branches))
        d.add_errback(logger.exception)

    def _on_get_branches(self, reply):
        """
        Called when the list of branches is received.

        :param reply: the reply from the server
        """
        self._branches = reply.branches
        self._refresh_branches()

    def _refresh_branches(self):
        """
        Refreshes the table of branches.
        """

        def createItem(text, branch):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, branch)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if branch.tick == -1:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            return item

        self._branchesTable.setRowCount(len(self._branches))
        for i, branch in enumerate(self._branches):
            self._branchesTable.setItem(i, 0, createItem(branch.name, branch))
            self._branchesTable.setItem(i, 1, createItem(branch.date, branch))
            tick = str(branch.tick) if branch.tick != -1 else '<none>'
            self._branchesTable.setItem(i, 2, createItem(tick, branch))

    def _branch_clicked(self):
        """
        Called when a branch item is clicked.
        """
        self._acceptButton.setEnabled(True)

    def _branch_double_clicked(self):
        """
        Called when a branch item is double-clicked.
        """
        self.accept()

    def get_result(self):
        """
        Get the result (repo, branch) from this dialog.

        :return: the result
        """
        repo = self._reposTable.selectedItems()[0].data(Qt.UserRole)
        return repo, self._branchesTable.selectedItems()[0].data(Qt.UserRole)


class SaveDialog(OpenDialog):
    """
    The save dialog allowing an user to select a remote database to upload to.
    """

    def __init__(self, plugin):
        """
        Initialize the save dialog.

        :param plugin: the plugin instance
        """
        super(SaveDialog, self).__init__(plugin)
        self._repo = None

        # General setup of the dialog
        self.setWindowTitle("Save to Remote Server")
        iconPath = self._plugin.resource('upload.png')
        self.setWindowIcon(QIcon(iconPath))

        # Setup the layout and widgets
        self._acceptButton.setText("Save")

        newRepoButton = QPushButton("New Repository", self._leftSide)
        newRepoButton.clicked.connect(self._new_repo_clicked)
        self._leftLayout.addWidget(newRepoButton)

        self._newBranchButton = QPushButton("New Branch", self._branchesGroup)
        self._newBranchButton.setEnabled(False)
        self._newBranchButton.clicked.connect(self._new_branch_clicked)
        self._branchesLayout.addWidget(self._newBranchButton)

    def _repo_clicked(self):
        super(SaveDialog, self)._repo_clicked()
        self._repo = self._reposTable.selectedItems()[0].data(Qt.UserRole)
        self._newBranchButton.setEnabled(True)

    def _new_repo_clicked(self):
        """
        Called when the new repository button is clicked.
        """
        dialog = NewRepoDialog(self._plugin)
        dialog.accepted.connect(partial(self._new_repo_accepted, dialog))
        dialog.exec_()

    def _new_repo_accepted(self, dialog):
        """
        Called when the new repository dialog is accepted by the user.

        :param dialog: the dialog
        """
        name = dialog.get_result()
        if any(repo.name == name for repo in self._repos):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A repository with that name already exists!")
            failure.setWindowTitle("New Repository")
            iconPath = self._plugin.resource('upload.png')
            failure.setWindowIcon(QIcon(iconPath))
            failure.exec_()
            return

        hash = ida_nalt.retrieve_input_file_md5().lower()
        file = ida_nalt.get_root_filename()
        type = ida_loader.get_file_type_name()
        dateFormat = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(dateFormat)
        repo = Repository(name, hash, file, type, date)
        d = self._plugin.network.send_packet(NewRepository.Query(repo))
        d.add_callback(partial(self._on_new_repo, repo))
        d.add_errback(logger.exception)

    def _on_new_repo(self, repo, _):
        """
        Called when the new repository reply is received.

        :param repo: the new repo
        """
        self._repos.append(repo)
        self._refresh_repos()
        row = len(self._repos) - 1
        self._reposTable.selectRow(row)
        self._acceptButton.setEnabled(False)

    def _refresh_repos(self):
        super(SaveDialog, self)._refresh_repos()
        hash = ida_nalt.retrieve_input_file_md5().lower()
        for row in range(self._reposTable.rowCount()):
            item = self._reposTable.item(row, 0)
            repo = item.data(Qt.UserRole)
            if repo.hash != hash:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _new_branch_clicked(self):
        """
        Called when the new branch button is clicked.
        """
        dialog = NewBranchDialog(self._plugin)
        dialog.accepted.connect(partial(self._new_branch_accepted, dialog))
        dialog.exec_()

    def _new_branch_accepted(self, dialog):
        """
        Called when the new branch dialog is accepted by the user.

        :param dialog: the dialog
        """
        name = dialog.get_result()
        if any(br.name == name for br in self._branches):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A branch with that name already exists!")
            failure.setWindowTitle("New Branch")
            iconPath = self._plugin.resource('upload.png')
            failure.setWindowIcon(QIcon(iconPath))
            failure.exec_()
            return

        dateFormat = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(dateFormat)
        branch = Branch(self._repo.name, name, date, -1)
        d = self._plugin.network.send_packet(NewBranch.Query(branch))
        d.add_callback(partial(self._on_new_branch, branch))
        d.add_errback(logger.exception)

    def _on_new_branch(self, branch, _):
        """
        Called when the new branch reply is received.

        :param branch: the new branch
        """
        self._branches.append(branch)
        self._refresh_branches()
        row = len(self._branches) - 1
        self._branchesTable.selectRow(row)

    def _refresh_branches(self):
        super(SaveDialog, self)._refresh_branches()
        for row in range(self._branchesTable.rowCount()):
            for col in range(3):
                item = self._branchesTable.item(row, col)
                item.setFlags(item.flags() | Qt.ItemIsEnabled)


class NewRepoDialog(QDialog):
    """
    The dialog allowing an user to create a new repository.
    """

    def __init__(self, plugin):
        """
        Initialize the new repo dialog.

        :param plugin: the plugin instance
        """
        super(NewRepoDialog, self).__init__()

        # General setup of the dialog
        logger.debug("New repo dialog")
        self.setWindowTitle("New Repository")
        iconPath = plugin.resource('upload.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(100, 100)

        layout = QVBoxLayout(self)

        self._nameLabel = QLabel("<b>Repository Name</b>")
        layout.addWidget(self._nameLabel)
        self._nameEdit = QLineEdit()
        self._nameEdit.setValidator(QRegExpValidator(QRegExp("[a-zA-Z0-9-]+")))
        layout.addWidget(self._nameEdit)

        buttons = QWidget(self)
        buttonsLayout = QHBoxLayout(buttons)
        createButton = QPushButton("Create")
        createButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(createButton)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(cancelButton)
        layout.addWidget(buttons)

    def get_result(self):
        """
        Get the user-specified name from this dialog.

        :return: the name
        """
        return self._nameEdit.text()


class NewBranchDialog(NewRepoDialog):
    """
    The dialog allowing an user to create a new branch.
    """

    def __init__(self, plugin):
        """
        Initialize the new branch dialog.

        :param plugin: the plugin instance
        """
        super(NewBranchDialog, self).__init__(plugin)
        self.setWindowTitle("New Branch")
        self._nameLabel.setText("<b>Branch Name</b>")


class SettingsDialog(QDialog):
    """
    The dialog allowing an user to select a remote server to connect to.
    """

    def __init__(self, plugin):
        """
        Initialize the settings dialog.

        :param plugin: the plugin instance
        """
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        logger.debug("Showing settings dialog")
        self.setWindowTitle("Settings")
        iconPath = self._plugin.resource('settings.png')
        self.setWindowIcon(QIcon(iconPath))
        self.finished.connect(self._commit)

        tabs = QTabWidget(self)

        # General Settings tab
        tab = QWidget(tabs)
        layout = QFormLayout(tab)
        layout.setFormAlignment(Qt.AlignVCenter)
        tabs.addTab(tab, "General Settings")

        userWidget = QWidget(tab)
        userLayout = QHBoxLayout(userWidget)
        layout.addRow(userWidget)

        # User color
        colorButton = QPushButton("")
        colorButton.setFixedSize(50, 30)

        def setColor(color):
            """
            Sets the color (if valid) as user's color

            :param color: the color
            """
            if color.isValid():
                r, g, b, _ = color.getRgb()
                # IDA represents color as 0xBBGGRR
                rgb_color_ida = b << 16 | g << 8 | r
                # Qt represents color as 0xRRGGBB
                rgb_color_qt = r << 16 | g << 8 | b
                css = 'QPushButton {background-color: #%06x; color: #%06x;}' \
                    % (rgb_color_qt, rgb_color_qt)
                colorButton.setStyleSheet(css)
                self._color = rgb_color_ida

        # Add a handler on clicking color button
        def colorButtonActivated(_):
            setColor(QColorDialog.getColor())

        self._color = self._plugin.config["user"]["color"]
        setColor(QColor(self._color))
        colorButton.clicked.connect(colorButtonActivated)
        userLayout.addWidget(colorButton)

        # User name
        self._nameLineEdit = QLineEdit()
        name = self._plugin.config["user"]["name"]
        self._nameLineEdit.setText(name)
        userLayout.addWidget(self._nameLineEdit)

        text = "Show other users in the navigation bar"
        self._navbarColorizerCheckbox = QCheckBox(text)
        layout.addRow(self._navbarColorizerCheckbox)
        checked = self._plugin.config["user"]["navbar_colorizer"]
        self._navbarColorizerCheckbox.setChecked(checked)

        text = "Allow other users to send notifications"
        self._notificationsCheckbox = QCheckBox(text)
        layout.addRow(self._notificationsCheckbox)
        checked = self._plugin.config["user"]["notifications"]
        self._notificationsCheckbox.setChecked(checked)

        # Log level
        debugLevelLabel = QLabel("Logging level: ")
        self._debugLevelComboBox = QComboBox()
        self._debugLevelComboBox.addItem("CRITICAL", logging.CRITICAL)
        self._debugLevelComboBox.addItem("ERROR", logging.ERROR)
        self._debugLevelComboBox.addItem("WARNING", logging.WARNING)
        self._debugLevelComboBox.addItem("INFO", logging.INFO)
        self._debugLevelComboBox.addItem("DEBUG", logging.DEBUG)
        self._debugLevelComboBox.addItem("TRACE", logging.TRACE)
        level = logger.getEffectiveLevel()
        index = self._debugLevelComboBox.findData(level)
        self._debugLevelComboBox.setCurrentIndex(index)
        layout.addRow(debugLevelLabel, self._debugLevelComboBox)

        # Network Settings tab
        tab = QWidget(tabs)
        layout = QVBoxLayout(tab)
        tab.setLayout(layout)
        tabs.addTab(tab, "Network Settings")

        topWidget = QWidget(tab)
        layout.addWidget(topWidget)
        topLayout = QHBoxLayout(topWidget)

        self._servers = list(self._plugin.config["servers"])
        self._serversTable = QTableWidget(len(self._servers), 2, self)
        topLayout.addWidget(self._serversTable)
        for i, server in enumerate(self._servers):
            item = QTableWidgetItem('%s:%d' % (server["host"], server["port"]))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if self._plugin.network.server == server:
                item.setFlags((item.flags() & ~Qt.ItemIsSelectable))
            self._serversTable.setItem(i, 0, item)

            checkbox = QTableWidgetItem()
            state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
            checkbox.setCheckState(state)
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsEditable))
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsUserCheckable))
            if self._plugin.network.server == server:
                checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsSelectable))
            self._serversTable.setItem(i, 1, checkbox)

        self._serversTable.setHorizontalHeaderLabels(("Servers", ""))
        horizontalHeader = self._serversTable.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)
        horizontalHeader.setSectionResizeMode(0, QHeaderView.Stretch)
        horizontalHeader.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._serversTable.verticalHeader().setVisible(False)
        self._serversTable.setSelectionBehavior(QTableWidget.SelectRows)
        self._serversTable.setSelectionMode(QTableWidget.SingleSelection)
        self._serversTable.itemClicked.connect(self._single_click)
        self._serversTable.itemDoubleClicked.connect(self._double_click)
        self._serversTable.setMaximumHeight(100)

        buttonsWidget = QWidget(topWidget)
        buttonsLayout = QVBoxLayout(buttonsWidget)
        topLayout.addWidget(buttonsWidget)

        # Add server button
        self._addButton = QPushButton("Add Server")
        self._addButton.clicked.connect(self._add_button_clicked)
        buttonsLayout.addWidget(self._addButton)

        # Edit server button
        self._editButton = QPushButton("Edit Server")
        self._editButton.setEnabled(False)
        self._editButton.clicked.connect(self._edit_button_clicked)
        buttonsLayout.addWidget(self._editButton)

        # Delete server button
        self._deleteButton = QPushButton("Delete Server")
        self._deleteButton.setEnabled(False)
        self._deleteButton.clicked.connect(self._delete_button_clicked)
        buttonsLayout.addWidget(self._deleteButton)

        bottomWidget = QWidget(tab)
        bottomLayout = QFormLayout(bottomWidget)
        layout.addWidget(bottomWidget)

        keepCntLabel = QLabel("Keep-Alive Count: ")
        self._keepCntSpinBox = QSpinBox(bottomWidget)
        self._keepCntSpinBox.setRange(0, 86400)
        self._keepCntSpinBox.setValue(self._plugin.config["keep"]["cnt"])
        self._keepCntSpinBox.setSuffix(" packets")
        bottomLayout.addRow(keepCntLabel, self._keepCntSpinBox)

        keepIntvlLabel = QLabel("Keep-Alive Interval: ")
        self._keepIntvlSpinBox = QSpinBox(bottomWidget)
        self._keepIntvlSpinBox.setRange(0, 86400)
        self._keepIntvlSpinBox.setValue(self._plugin.config["keep"]["intvl"])
        self._keepIntvlSpinBox.setSuffix(" seconds")
        bottomLayout.addRow(keepIntvlLabel, self._keepIntvlSpinBox)

        keepIdleLabel = QLabel("Keep-Alive Idle: ")
        self._keepIdleSpinBox = QSpinBox(bottomWidget)
        self._keepIdleSpinBox.setRange(0, 86400)
        self._keepIdleSpinBox.setValue(self._plugin.config["keep"]["idle"])
        self._keepIdleSpinBox.setSuffix(" seconds")
        bottomLayout.addRow(keepIdleLabel, self._keepIdleSpinBox)

        self.resize(tab.sizeHint().width() + 5, tab.sizeHint().height() + 30)

    def _single_click(self, _):
        """
        Called when a server item is clicked.
        """
        self._editButton.setEnabled(True)
        self._deleteButton.setEnabled(True)

    def _double_click(self, _):
        item = self._serversTable.selectedItems()[0]
        server = item.data(Qt.UserRole)
        if not self._plugin.network.connected \
                or self._plugin.network.server != server:
            self._plugin.network.stop_server()
            self._plugin.network.connect(server)
        self.accept()

    def _add_button_clicked(self, _):
        """
        Called when the add button is clicked.
        """
        dialog = ServerInfoDialog(self._plugin, "Add server")
        dialog.accepted.connect(partial(self._add_dialog_accepted, dialog))
        dialog.exec_()

    def _edit_button_clicked(self, _):
        """
        Called when the add button is clicked.
        """
        item = self._serversTable.selectedItems()[0]
        server = item.data(Qt.UserRole)
        dialog = ServerInfoDialog(self._plugin, "Edit server", server)
        dialog.accepted.connect(partial(self._edit_dialog_accepted, dialog))
        dialog.exec_()

    def _add_dialog_accepted(self, dialog):
        """
        Called when the add server dialog is accepted by the user.

        :param dialog: the add server dialog
        """
        server = dialog.get_result()
        self._servers.append(server)
        rowCount = self._serversTable.rowCount()
        self._serversTable.insertRow(rowCount)

        newServer = QTableWidgetItem('%s:%d' %
                                     (server["host"], server["port"]))
        newServer.setData(Qt.UserRole, server)
        newServer.setFlags(newServer.flags() & ~Qt.ItemIsEditable)
        self._serversTable.setItem(rowCount, 0, newServer)

        newCheckbox = QTableWidgetItem()
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        newCheckbox.setCheckState(state)
        newCheckbox.setFlags((newCheckbox.flags() & ~Qt.ItemIsEditable))
        newCheckbox.setFlags(newCheckbox.flags() & ~Qt.ItemIsUserCheckable)
        self._serversTable.setItem(rowCount, 1, newCheckbox)
        self.update()

    def _edit_dialog_accepted(self, dialog):
        """
        Called when the add server dialog is accepted by the user.

        :param dialog: the edit server dialog
        """
        server = dialog.get_result()
        item = self._serversTable.selectedItems()[0]
        self._servers[item.row()] = server

        item.setText('%s:%d' % (server["host"], server["port"]))
        item.setData(Qt.UserRole, server)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        checkbox = self._serversTable.item(item.row(), 1)
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        checkbox.setCheckState(state)
        self.update()

    def _delete_button_clicked(self, _):
        """
        Called when the delete button is clicked.
        """
        item = self._serversTable.selectedItems()[0]
        server = item.data(Qt.UserRole)
        self._servers.remove(server)
        self._plugin.save_config()
        self._serversTable.removeRow(item.row())
        self.update()

    def _commit(self, _):
        checked = self._navbarColorizerCheckbox.isChecked()
        self._plugin.config["user"]["navbar_colorizer"] = checked

        checked = self._notificationsCheckbox.isChecked()
        self._plugin.config["user"]["notifications"] = checked

        name = self._nameLineEdit.text()
        if self._plugin.config["user"]["name"] != name:
            old_name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(UserRenamed(old_name, name))
            self._plugin.config["user"]["name"] = name

        if self._plugin.config["user"]["color"] != self._color:
            name = self._plugin.config["user"]["name"]
            old_color = self._plugin.config["user"]["color"]
            packet = UserColorChanged(name, old_color, self._color)
            self._plugin.network.send_packet(packet)
            self._plugin.config["user"]["color"] = self._color

        from idarling.plugin import logger
        index = self._debugLevelComboBox.currentIndex()
        level = self._debugLevelComboBox.itemData(index)
        logger.setLevel(level)
        self._plugin.config["level"] = level

        self._plugin.config["servers"] = self._servers
        cnt = self._keepCntSpinBox.value()
        self._plugin.config["keep"]["cnt"] = cnt
        intvl = self._keepIntvlSpinBox.value()
        self._plugin.config["keep"]["intvl"] = intvl
        idle = self._keepIdleSpinBox.value()
        self._plugin.config["keep"]["idle"] = idle
        if self._plugin.network.client:
            self._plugin.network.client.set_keep_alive(cnt, intvl, idle)

        self._plugin.save_config()


class ServerInfoDialog(QDialog):
    """
    The dialog allowing an user to add a remote server to connect to.
    """

    def __init__(self, plugin, title, server=None):
        """
        Initialize the network setting dialog.

        :param plugin: the plugin instance
        :param title: the dialog title
        :param server: the current server information
        """
        super(ServerInfoDialog, self).__init__()

        # General setup of the dialog
        logger.debug("Showing server info dialog")
        self.setWindowTitle(title)
        iconPath = plugin.resource('settings.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(100, 100)

        layout = QVBoxLayout(self)

        self._serverNameLabel = QLabel("<b>Server Host</b>")
        layout.addWidget(self._serverNameLabel)
        self._serverName = QLineEdit()
        self._serverName.setPlaceholderText("127.0.0.1")
        layout.addWidget(self._serverName)

        self._serverNameLabel = QLabel("<b>Server Port</b>")
        layout.addWidget(self._serverNameLabel)
        self._serverPort = QLineEdit()
        self._serverPort.setPlaceholderText("31013")
        layout.addWidget(self._serverPort)

        self._noSSLCheckbox = QCheckBox("Disable SSL")
        layout.addWidget(self._noSSLCheckbox)

        if server is not None:
            self._serverName.setText(server["host"])
            self._serverPort.setText(str(server["port"]))
            self._noSSLCheckbox.setChecked(server["no_ssl"])

        downSide = QWidget(self)
        buttonsLayout = QHBoxLayout(downSide)
        self._addButton = QPushButton("OK")
        self._addButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(self._addButton)
        self._cancelButton = QPushButton("Cancel")
        self._cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(self._cancelButton)
        layout.addWidget(downSide)

    def get_result(self):
        """
        Get the result (server, port) from this dialog.

        :return: the result
        """
        new_server = {
            "host": self._serverName.text() or "127.0.0.1",
            "port": int(self._serverPort.text() or "31013"),
            "no_ssl": self._noSSLCheckbox.isChecked()
        }
        return new_server
