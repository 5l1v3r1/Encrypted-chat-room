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
from PyQt5.QtCore import Qt, QStringListModel
from PyQt5.QtGui import QKeyEvent
from PyQt5.QtWidgets import QListWidgetItem, QDesktopWidget
from utils.tools import verify_username
from quamash import QEventLoop
from base64 import b64encode
import functools

with open('server_public_key', 'r') as f:
    server_public_key = rsa.PublicKey.load_pkcs1(f.read())

client: Client
app = QtWidgets.QApplication(sys.argv)
loop = QEventLoop(app)
asyncio.set_event_loop(loop)


def wrap_in_future(func):
    @functools.wraps(func)
    def wrapper(*args, **kw):
        asyncio.ensure_future(func(*args, **kw))

    return wrapper


def move_window_center(window):
    qt_rectangle = window.frameGeometry()
    center_point = QDesktopWidget().availableGeometry().center()
    qt_rectangle.moveCenter(center_point)
    window.move(qt_rectangle.topLeft())


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

    @wrap_in_future
    async def login(self, dummy):
        global client
        global server_public_key

        try:
            server_addr = self.text_server_addr.text()
            server_port = int(self.text_server_port.text())
            client = await get_client(server_addr, server_port, server_public_key)
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

        register_res = await client.send_register(public_key, username)
        login_res = await client.send_login(private_key, username)

        if not register_res['success'] and not login_res['success']:
            QtWidgets.QMessageBox.warning(None, " ", "这个用户名已经有人使用, 或者私钥文件不正确")
            client.writer.close()
            return

        self.save_last_settings()
        self.hide()
        main_window.show()
        await main_window.start_listen()

    def get_public_key(self):
        public_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择用户私钥文件", '.', "JSON (*.json)")
        if public_key_path:
            self.private_key_path = public_key_path
            self.btn_public_key.setText(basename(public_key_path))


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.list_users.clicked.connect(self.switch_history)
        self.btn_send.clicked.connect(self.send_message)
        self.btn_look_key.clicked.connect(self.show_aes_key)

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

    def refresh_user_list(self, client: Client, response):
        self.users = set(response['data'])
        self.users.add(self.public_room_name)
        for username in self.users:
            self.history[username] = []
            client.send_dh_request(username, True)  # 发送握手请求

        self.list_users.setModel(QStringListModel(self.users))

    def user_online(self, client: Client, response):
        username = response['data']
        self.history[username] = []

        self.users.add(username)
        client.send_dh_request(username, True)  # 发送握手请求
        self.list_users.setModel(QStringListModel(self.users))

    def user_offline(self, client: Client, response):
        username = response['data']
        self.users.remove(username)
        self.history.pop(username)
        self.list_users.setModel(QStringListModel(self.users))
        if self.curr_select == username:  # 当前选择用户是下线的用户时, 刷新聊天框
            self.curr_select = self.public_room_name
            self.refresh_history(self.history[self.public_room_name])

    def kicked(self, client: Client, response):
        QtWidgets.QMessageBox.warning(None, " ", "您已经被踢下线, 如果非本人操作, 请确认私钥是否泄露")
        self.close()

    def show_aes_key(self):
        if self.curr_select == self.public_room_name:
            message = "公共房间只存在 客户端-服务端 加密"
        else:
            message = b64encode(client.user_dh_keys[self.curr_select]['dh_common_key']).decode()
        QtWidgets.QMessageBox.warning(None, " ", message)

    def handle_send_everyone(self, client: Client, response):
        response['data']['me'] = False
        response['data']['time'] = time.strftime('%H:%M:%S')
        self.history[self.public_room_name].append(response['data'])
        if self.curr_select == self.public_room_name:
            self.refresh_history(self.history[self.public_room_name])

    def handle_send_user(self, client: Client, response):
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

    async def start_listen(self):
        callbacks = {
            'list': self.refresh_user_list,
            'kicked': self.kicked,
            'online': self.user_online,
            'offline': self.user_offline,
            'send_everyone': self.handle_send_everyone,
            'send_user': self.handle_send_user
        }
        global client
        self.lab_username.setText(client.username)
        client.send_get_users()
        await client.start_listen(callbacks)


login = Login()
move_window_center(login)
login.show()
main_window = MainWindow()
move_window_center(main_window)
sys.exit(app.exec_())
