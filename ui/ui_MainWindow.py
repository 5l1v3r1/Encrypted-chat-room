# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.12.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setFixedSize(729, 577)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.list_users = QtWidgets.QListView(self.centralwidget)
        self.list_users.setGeometry(QtCore.QRect(0, 0, 160, 571))
        self.list_users.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.list_users.setObjectName("list_users")
        self.text_msg = QtWidgets.QTextEdit(self.centralwidget)
        self.text_msg.setGeometry(QtCore.QRect(160, 450, 570, 90))
        self.text_msg.setObjectName("text_msg")
        self.btn_send = QtWidgets.QPushButton(self.centralwidget)
        self.btn_send.setGeometry(QtCore.QRect(640, 540, 91, 40))
        self.btn_send.setObjectName("btn_send")
        self.list_history = QtWidgets.QListWidget(self.centralwidget)
        self.list_history.setGeometry(QtCore.QRect(160, 0, 570, 451))
        self.list_history.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.list_history.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.list_history.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.list_history.setObjectName("list_history")
        self.lab_user = QtWidgets.QLabel(self.centralwidget)
        self.lab_user.setGeometry(QtCore.QRect(170, 550, 71, 21))
        self.lab_user.setObjectName("lab_user")
        self.lab_username = QtWidgets.QLabel(self.centralwidget)
        self.lab_username.setGeometry(QtCore.QRect(250, 550, 260, 21))
        self.lab_username.setText("")
        self.lab_username.setObjectName("lab_username")
        self.btn_look_key = QtWidgets.QPushButton(self.centralwidget)
        self.btn_look_key.setGeometry(QtCore.QRect(530, 540, 110, 40))
        self.btn_look_key.setObjectName("btn_look_key")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Chatroom"))
        self.btn_send.setText(_translate("MainWindow", "发送"))
        self.lab_user.setText(_translate("MainWindow", "用户名:"))
        self.btn_look_key.setText(_translate("MainWindow", "查看共有秘钥"))


