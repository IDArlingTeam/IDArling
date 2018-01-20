import logging

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QFormLayout,
    QWidget, QTableWidget, QTableWidgetItem,
    QGroupBox, QLabel, QLineEdit, QPushButton)

from idaconnect.util import *


logger = logging.getLogger('IDAConnect.Dialogs')


class OpenDialog(QDialog):

    def __init__(self, plugin, dbs):
        super(OpenDialog, self).__init__()
        self._plugin = plugin

        logger.debug("Showing open database dialog")
        self.setWindowTitle("Open from Remote Server")
        iconPath = self._plugin.getResource('open.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(600, 300)

        layout = QHBoxLayout(self)
        self._leftSide = QTableWidget(3, 1, self)
        self._leftSide.setHorizontalHeaderLabels(('Remote Databases',))
        for i, db in enumerate(dbs):
            item = QTableWidgetItem(db[0])
            item.setData(Qt.UserRole, db)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._leftSide.setItem(i, 0, item)
        self._leftSide.horizontalHeader().setSectionsClickable(False)
        self._leftSide.horizontalHeader().setStretchLastSection(True)
        self._leftSide.verticalHeader().setVisible(False)
        self._leftSide.setSelectionBehavior(QTableWidget.SelectItems)
        self._leftSide.setSelectionMode(QTableWidget.SingleSelection)
        self._leftSide.itemClicked.connect(self._itemClicked)
        layout.addWidget(self._leftSide)

        rightSide = QWidget(self)
        rightLayout = QVBoxLayout(rightSide)
        detailsGroup = QGroupBox("Details", rightSide)
        detailsLayout = QFormLayout(detailsGroup)
        self._nameEdit = QLineEdit()
        self._nameEdit.setReadOnly(True)
        detailsLayout.addRow(QLabel("Name:"), self._nameEdit)
        self._hashEdit = QLineEdit()
        self._hashEdit.setReadOnly(True)
        detailsLayout.addRow(QLabel("Hash:"), self._hashEdit)
        rightLayout.addWidget(detailsGroup)
        rightLayout.addStretch()

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

    def _itemClicked(self, item):
        db = item.data(Qt.UserRole)
        self._nameEdit.setText(db[0])
        self._hashEdit.setText(db[1])
        self._openButton.setEnabled(True)

    def getDatabase(self):
        return self._leftSide.currentItem().data(Qt.UserRole)


class SaveDialog(QDialog):

    def __init__(self, plugin, dbs, db):
        super(SaveDialog, self).__init__()
        self._plugin = plugin
        self._db = None

        logger.debug("Showing save database dialog")
        self.setWindowTitle("Save to Remote Server")
        iconPath = self._plugin.getResource('save.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(600, 300)

        layout = QHBoxLayout(self)
        self._leftSide = QTableWidget(3, 1, self)
        self._leftSide.setHorizontalHeaderLabels(('Remote Databases',))
        for i, db_ in enumerate(dbs):
            item = QTableWidgetItem(db_[0])
            item.setData(Qt.UserRole, db_)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._leftSide.setItem(i, 0, item)
        self._leftSide.horizontalHeader().setSectionsClickable(False)
        self._leftSide.horizontalHeader().setStretchLastSection(True)
        self._leftSide.verticalHeader().setVisible(False)
        self._leftSide.setSelectionBehavior(QTableWidget.SelectItems)
        self._leftSide.setSelectionMode(QTableWidget.SingleSelection)
        self._leftSide.itemClicked.connect(self._itemClicked)
        layout.addWidget(self._leftSide)

        rightSide = QWidget(self)
        rightLayout = QVBoxLayout(rightSide)
        newGroup = QGroupBox("Create a new database", rightSide)
        newLayout = QHBoxLayout(newGroup)
        newRight = QWidget(newGroup)
        newRightLayout = QFormLayout(newRight)
        self._newNameEdit = QLineEdit(db[0])
        newRightLayout.addRow(QLabel("Name:"), self._newNameEdit)
        self._newHashEdit = QLineEdit(db[1])
        self._newHashEdit.setReadOnly(True)
        newRightLayout.addRow(QLabel("Hash:"), self._newHashEdit)
        newLayout.addWidget(newRight)
        self._newButton = QPushButton("New")
        self._newButton.clicked.connect(self._newClicked)
        newLayout.addWidget(self._newButton)
        rightLayout.addWidget(newGroup)
        rightLayout.addStretch()

        useGroup = QGroupBox("Use existing database", rightSide)
        useLayout = QFormLayout(useGroup)
        self._useNameEdit = QLineEdit()
        self._useNameEdit.setReadOnly(True)
        useLayout.addRow(QLabel("Name:"), self._useNameEdit)
        self._useHashEdit = QLineEdit()
        self._useHashEdit.setReadOnly(True)
        useLayout.addRow(QLabel("Hash:"), self._useHashEdit)
        rightLayout.addWidget(useGroup)
        rightLayout.addStretch()

        buttonsWidget = QWidget(rightSide)
        buttonsLayout = QHBoxLayout(buttonsWidget)
        buttonsLayout.addStretch()
        self._openButton = QPushButton("Save")
        self._openButton.setEnabled(False)
        self._openButton.clicked.connect(self.accept)
        buttonsLayout.addWidget(self._openButton)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self.reject)
        buttonsLayout.addWidget(cancelButton)
        rightLayout.addWidget(buttonsWidget)
        layout.addWidget(rightSide)

    def _itemClicked(self, item):
        db = item.data(Qt.UserRole)
        self._useNameEdit.setText(db[0])
        self._useHashEdit.setText(db[1])
        self._openButton.setEnabled(True)

    def _newClicked(self):
        self._db = (self._newNameEdit.text(), self._newHashEdit.text())
        self.accept()

    def getDatabase(self):
        if self._db:
            return self._db
        return self._leftSide.currentItem().data(Qt.UserRole)
