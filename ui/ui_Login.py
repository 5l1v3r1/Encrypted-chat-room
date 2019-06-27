# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Login.ui'
#
# Created by: PyQt5 UI code generator 5.12.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Login(object):
    def setupUi(self, Login):
        Login.setObjectName("Login")
        Login.setFixedSize(394, 228)
        self.btn_login = QtWidgets.QPushButton(Login)
        self.btn_login.setGeometry(QtCore.QRect(160, 170, 95, 40))
        self.btn_login.setObjectName("btn_login")
        self.text_username = QtWidgets.QLineEdit(Login)
        self.text_username.setGeometry(QtCore.QRect(140, 80, 180, 34))
        self.text_username.setObjectName("text_username")
        self.lab_username = QtWidgets.QLabel(Login)
        self.lab_username.setGeometry(QtCore.QRect(70, 90, 60, 21))
        self.lab_username.setObjectName("lab_username")
        self.lan_public_key = QtWidgets.QLabel(Login)
        self.lan_public_key.setGeometry(QtCore.QRect(60, 130, 72, 21))
        self.lan_public_key.setObjectName("lan_public_key")
        self.btn_public_key = QtWidgets.QPushButton(Login)
        self.btn_public_key.setGeometry(QtCore.QRect(150, 120, 160, 40))
        self.btn_public_key.setObjectName("btn_public_key")
        self.lab_server_addr = QtWidgets.QLabel(Login)
        self.lab_server_addr.setGeometry(QtCore.QRect(80, 30, 40, 21))
        self.lab_server_addr.setObjectName("lab_server_addr")
        self.lab_server_port = QtWidgets.QLabel(Login)
        self.lab_server_port.setGeometry(QtCore.QRect(80, 60, 40, 21))
        self.lab_server_port.setObjectName("lab_server_port")
        self.text_server_port = QtWidgets.QLineEdit(Login)
        self.text_server_port.setGeometry(QtCore.QRect(140, 50, 180, 34))
        self.text_server_port.setObjectName("text_server_port")
        self.text_server_addr = QtWidgets.QLineEdit(Login)
        self.text_server_addr.setGeometry(QtCore.QRect(140, 20, 180, 34))
        self.text_server_addr.setObjectName("text_server_addr")

        self.retranslateUi(Login)
        QtCore.QMetaObject.connectSlotsByName(Login)

    def retranslateUi(self, Login):
        _translate = QtCore.QCoreApplication.translate
        Login.setWindowTitle(_translate("Login", "登录"))
        self.btn_login.setText(_translate("Login", "登录"))
        self.lab_username.setText(_translate("Login", "用户名"))
        self.lan_public_key.setText(_translate("Login", "公钥路径"))
        self.btn_public_key.setText(_translate("Login", "未选择"))
        self.lab_server_addr.setText(_translate("Login", "地址"))
        self.lab_server_port.setText(_translate("Login", "端口"))


