import sys   # noqa
sys.path.append('../..')  # noqa

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QFormLayout,
    QWidget, QTableWidget, QTableWidgetItem,
    QGroupBox, QLabel, QLineEdit, QPushButton)

from idaconnect.util import *


class OpenDatabase(QDialog):

    def __init__(self, databases):
        super(OpenDatabase, self).__init__()
        self.setWindowTitle("Open from Remote Server")
        iconPath = getPluginResource('open.png')
        self.setWindowIcon(QIcon(iconPath))
        self.resize(600, 300)

        layout = QHBoxLayout(self)
        self._leftSide = QTableWidget(3, 1, self)
        self._leftSide.setHorizontalHeaderLabels(('Remote Databases',))
        for i, db in enumerate(databases):
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
