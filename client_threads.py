from ui.ui_Login import Ui_Login
from ui.ui_MainWindow import Ui_MainWindow
from PyQt5 import QtWidgets
import sys
from classes.client import get_client, Client
import asyncio
from os.path import basename, exists
import rsa
import json
import time
from PyQt5.QtCore import QThread, Qt, QStringListModel
from PyQt5.QtGui import QKeyEvent
from PyQt5.QtWidgets import QListWidgetItem
from utils.tools import verify_username

with open('server_public_key', 'r') as f:
    server_public_key = rsa.PublicKey.load_pkcs1(f.read())

client: Client
loop = asyncio.get_event_loop()


class Login(QtWidgets.QWidget, Ui_Login):
    private_key_path = ""
    thread = None

    def save_last_settings(self):
        data = {
            'server_addr': self.text_server_addr.text(),
            'server_port': self.text_server_port.text(),
            'username': self.text_username.text(),
            'private_key_path': self.private_key_path
        }
        with open('.settings.json', 'w') as f:
            f.write(json.dumps(data))

    def load_last_settings(self):
        if exists('.settings.json'):
            with open('.settings.json', 'r') as f:
                data = f.read()
                data = json.loads(data)
                self.text_server_addr.setText(data['server_addr'])
                self.text_server_port.setText(data['server_port'])
                self.text_username.setText(data['username'])
                self.private_key_path = data['private_key_path']
                self.btn_public_key.setText(basename(self.private_key_path))

    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        Ui_Login.__init__(self)
        self.setupUi(self)

        self.btn_login.clicked.connect(self.login)
        self.btn_public_key.clicked.connect(self.get_public_key)

        self.load_last_settings()

    def login(self):
        global client
        global server_public_key

        try:
            server_addr = self.text_server_addr.text()
            server_port = int(self.text_server_port.text())
            task = asyncio.ensure_future(get_client(server_addr, server_port, server_public_key))
            loop.run_until_complete(task)
            client = task.result()
        except Exception:
            QtWidgets.QMessageBox.warning(None, " ", "无法连接到服务器")
            return

        username = self.text_username.text()
        if not verify_username(username):
            QtWidgets.QMessageBox.warning(None, " ", "输入有效的用户名")
            return

        with open(self.private_key_path, 'r') as f:
            data = json.loads(f.read())
            private_key = rsa.PrivateKey.load_pkcs1(data['private_key'])
            public_key = rsa.PublicKey.load_pkcs1(data['public_key'])

        task = asyncio.ensure_future(client.send_register(public_key, username))
        loop.run_until_complete(task)
        register_res = task.result()

        task = asyncio.ensure_future(client.send_login(private_key, username))

        loop.run_until_complete(task)
        login_res = task.result()

        if not register_res['success'] and not login_res['success']:
            QtWidgets.QMessageBox.warning(None, " ", "这个用户名已经有人使用, 或者私钥文件不正确")
            client.writer.close()
            return

        self.save_last_settings()
        self.hide()

        runner = Runner()
        runner.start()
        self.thread = runner

    def get_public_key(self):
        public_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择用户私钥文件", '.', "JSON (*.json)")
        if public_key_path:
            self.private_key_path = public_key_path
            self.btn_public_key.setText(basename(public_key_path))


class Runner(QThread):
    def run(self):
        main_window = MainWindow()
        main_window.show()
        main_window.start_listen()


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.list_users.clicked.connect(self.switch_history)
        self.btn_send.clicked.connect(self.send_message)

        self.text_msg_key_press_event = self.text_msg.keyPressEvent
        self.text_msg.keyPressEvent = self.keyPressEvent

        self.users = set()
        self.history = dict()

        self.public_room_name = "<公共聊天>"
        self.curr_select = self.public_room_name

    def keyPressEvent(self, event):
        key_event = QKeyEvent(event)
        if key_event.key() == 16777220:
            self.send_message()
        else:
            self.text_msg_key_press_event(event)

    def refresh_user_list(self, client:Client, response):
        self.users = set(response['data'])
        self.users.add(self.public_room_name)
        for username in self.users:
            self.history[username] = []
            client.send_dh_request(username, True)  # 发送握手请求

        self.list_users.setModel(QStringListModel(self.users))

    def user_online(self, client:Client, response):
        username = response['data']
        self.history[username] = []

        self.users.add(username)
        client.send_dh_request(username, True)  # 发送握手请求
        self.list_users.setModel(QStringListModel(self.users))

    def user_offline(self, client:Client, response):
        username = response['data']
        self.users.remove(username)
        self.history.pop(username)
        self.list_users.setModel(QStringListModel(self.users))
        if self.curr_select == username:  # 当前选择用户是下线的用户时, 刷新聊天框
            self.curr_select = self.public_room_name
            self.refresh_history(self.history[self.public_room_name])

    def kicked(self, client:Client, response):
        global app
        QtWidgets.QMessageBox.warning(None, " ", "您已经被踢下线, 如果非本人操作, 请确认私钥是否泄露")
        self.close()

    def handle_send_everyone(self, client:Client, response):
        response['data']['me'] = False
        response['data']['time'] = time.strftime('%H:%M:%S')
        self.history[self.public_room_name].append(response['data'])
        if self.curr_select == self.public_room_name:
            self.refresh_history(self.history[self.public_room_name])

    def handle_send_user(self, client:Client, response):
        response['data']['me'] = False
        response['data']['time'] = time.strftime('%H:%M:%S')
        self.history[response['data']['from']].append(response['data'])
        if self.curr_select == response['data']['from']:
            self.refresh_history(self.history[response['data']['from']])

    def refresh_history(self, history):
        self.list_history.clear()

        for i in history:
            item_a = QListWidgetItem(f"{i['from']} in {i['time']}:  ")
            item_b = QListWidgetItem(i['message'] + "  ")
            if i['me']:
                item_a.setTextAlignment(Qt.AlignRight)
                item_b.setTextAlignment(Qt.AlignRight)
            else:
                item_a.setTextAlignment(Qt.AlignLeft)
                item_b.setTextAlignment(Qt.AlignLeft)
            self.list_history.addItem(item_a)
            self.list_history.addItem(item_b)

        self.list_history.scrollToBottom()

    def switch_history(self):
        username = self.list_users.currentIndex().data()
        self.curr_select = username
        self.refresh_history(self.history[username])

    def send_message(self):
        global client
        message = self.text_msg.toPlainText().strip()
        if message != "":
            target = ""
            if self.curr_select == self.public_room_name:
                client.send_to_everyone(message)
                target = self.public_room_name
            else:
                client.send_to_user(self.curr_select, message)
                target = self.curr_select
            self.history[target].append({
                'from': client.username,
                'message': message,
                'me': True,
                'time': time.strftime('%H:%M:%S')
            })
            self.refresh_history(self.history[target])
            self.text_msg.clear()

    def start_listen(self):
        callbacks = {
            'list': self.refresh_user_list,
            'kicked': self.kicked,
            'online': self.user_online,
            'offline': self.user_offline,
            'send_everyone': self.handle_send_everyone,
            'send_user': self.handle_send_user
        }
        global client
        client.send_get_users()
        loop.run_until_complete(client.start_listen(callbacks))


app = QtWidgets.QApplication(sys.argv)
login = Login()
login.show()
sys.exit(app.exec_())
