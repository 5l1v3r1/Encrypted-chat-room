import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from utils.protocols import *
from utils.model import User, SQLAlchemy
from utils.tools import *
from base64 import b64decode, b64encode
import time
import rsa
from functools import wraps
import traceback
from selectors import EpollSelector
import logging

_selector = EpollSelector()
_loop = asyncio.SelectorEventLoop(_selector)
asyncio.set_event_loop(_loop)

engine = create_engine('sqlite:///user.db')
SQLAlchemy.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

global_users = dict()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Server(DH):
    session: Session
    public_key: rsa.PublicKey
    private_key: rsa.PrivateKey
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader

    login = False
    died = False
    username = ""
    challenge = ""

    handshake = False
    client_count = 0
    server_count = 0
    aes_gcm_key = b''

    def __init__(self, reader, writer, private_key, public_key):
        self.public_key = public_key
        self.private_key = private_key
        self.session = Session()
        self.writer = writer
        self.reader = reader

    def verify_timestamp(self, timestamp):
        if time.time() + 3 > timestamp and time.time() - 3 < timestamp:
            return True
        else:
            return False

    def add_server_count(self):
        self.server_count += 1
        if self.server_count == 18446744073709551616:
            self.server_count = 0

    def add_client_count(self):
        self.client_count += 1
        if self.client_count == 18446744073709551616:
            self.client_count = 0

    def login_required(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.login:
                return func(self, *args, **kwargs)
            else:
                return {'success': False, 'msg': '请先登录'}

        return wrapper

    def handle_handshake(self, request):
        dh_private = self.dh_gen_private()
        dh_public = self.dh_get_public(dh_private)

        dh_public = dh_public.to_bytes(233, 'big')
        dh_public_sign = rsa.sign(dh_public, self.private_key, 'SHA-512')

        dh_other_public = b64decode(request['dh_public'])
        client_count = b64decode(request['client_count'])
        server_count = b64decode(request['server_count'])

        dh_other_public = rsa.decrypt(dh_other_public, self.private_key)
        client_count = rsa.decrypt(client_count, self.private_key)
        server_count = rsa.decrypt(server_count, self.private_key)

        dh_other_public = int.from_bytes(dh_other_public, 'big')
        tmp_key = self.dh_get_common_key(dh_private, dh_other_public)
        self.aes_gcm_key = sha3_256(tmp_key)

        self.client_count = unpack('>Q', client_count)[0]
        self.server_count = unpack('>Q', server_count)[0]
        self.handshake = True
        res = {
            'success': True,
            'data': {
                'dh_public': b64encode(dh_public).decode('utf-8'),
                'sign': b64encode(dh_public_sign).decode('utf-8')
            }
        }
        return res

    def handle_register(self, request):
        public_key = request['pubkey']
        if vaild_public_key(public_key) and verify_username(request['username']):
            count = self.session.query(User).filter_by(username=request['username']).count()
            if count == 0:
                u = User()
                u.username = request['username']
                u.public_key = public_key
                u.key_hash = sha3_256(public_key)
                self.session.add(u)
                self.session.commit()
                res = {'success': True, 'msg': '注册成功'}
            else:
                res = {'success': False, 'msg': '已经有同名用户辣'}
        else:
            res = {'success': False}
        return res

    def handle_get_challenge(self, request):
        self.challenge = random_string()
        return {'success': True, 'data': {'challenge': self.challenge}}

    def handle_login(self, request):
        if self.challenge != "" and verify_username(request['username']):
            sign = b64decode(request['sign'])
            username = request['username']
            if self.session.query(User).filter_by(username=username).count():
                u = self.session.query(User).filter_by(username=username).one()
                public_key = rsa.PublicKey.load_pkcs1(u.public_key)
                try:
                    ret = rsa.verify(self.challenge.encode(), sign, public_key)
                    assert ret == 'SHA-512'
                    res = {'success': True, 'msg': '登录成功'}
                    self.login = True
                    self.username = request['username']

                    if self.username in global_users:  # 将对方踢下线
                        global_users[self.username].push_data('kicked', {})
                        global_users[self.username].died = True
                        global_users[self.username].writer.close()
                        logger.info(f'{self.username} 被踢下线')
                    global_users[self.username] = self
                    logger.info(f'{self.username} 上线')

                    for username in global_users:
                        if username != self.username:
                            server = global_users[username]
                            server.push_data('online', self.username)
                except Exception:
                    res = {'success': False, 'msg': '私钥错误'}
            else:
                res = {'success': False, 'msg': '用户不存在'}
        else:
            res = {'success': False}
        self.challenge = ""
        return res

    @login_required
    def handle_send_everyone(self, request):
        for username in global_users:
            if username != self.username:
                server: Server = global_users[username]
                data = {
                    'from': self.username,
                    'message': request['message']
                }
                server.push_data('send_everyone', data)
        res = {'success': True, 'type': 'send_everyone_info'}
        return res

    @login_required
    def handle_dh_request(self, request):
        username = request['username']
        request.pop('username')
        request['from'] = self.username
        if username in global_users:
            server = global_users[username]
            server.push_data('dh_request', request)
            res = {'success': True, 'type': 'dh_request_info'}
        else:
            res = {'success': False, 'type': 'dh_request_info'}
        return res

    @login_required
    def handle_send_user(self, request):
        username = request['username']
        request.pop('username')
        request['from'] = self.username
        if username in global_users:
            server = global_users[username]
            server.push_data('send_user', request)
            res = {'success': True, 'type': 'send_user_info'}
        else:
            res = {'success': False, 'type': 'send_user_info'}
        return res

    @login_required
    def handel_list(self, request):
        users = set(global_users.keys())
        users.remove(self.username)
        users = list(users)
        return {'success': True, 'type': 'list', 'data': users}

    def handle_default(self, request):
        return {'success': False, 'msg': '不支持的请求类型'}

    def handle_request(self, request):
        handle_dict = {
            'register': self.handle_register,
            'get_challenge': self.handle_get_challenge,
            'login': self.handle_login,
            'list': self.handel_list,
            'send_everyone': self.handle_send_everyone,
            'dh_request': self.handle_dh_request,
            'send_user': self.handle_send_user
        }
        func = handle_dict.get(request['type'], self.handle_default)
        return func(request['data'])

    def push_data(self, req_type, data):
        data = {
            'type': req_type,
            'data': data
        }
        logger.debug(f'{self.username}: {data}')
        data = pack_enc_data(data, self.server_count, self.aes_gcm_key)

        self.add_server_count()
        self.writer.write(data)

    async def start_listen(self):
        try:
            while True:
                length = await self.reader.readexactly(4)

                if self.reader.at_eof() or self.died:  # 判断链接是否结束
                    return
                else:
                    length = read_length(length)
                    request = await self.reader.readexactly(length)

                    if not self.handshake:
                        request = unpack_data(request)
                        response = self.handle_handshake(request)
                        response = pack_data(response)
                    else:
                        request = unpack_enc_data(request, self.client_count, self.aes_gcm_key)
                        self.add_client_count()
                        if not self.verify_timestamp(request['timestamp']):
                            self.died = True
                            return  # 检验时间戳不正确, 可能遇到重放攻击
                        response = self.handle_request(request)
                        response = pack_enc_data(response, self.server_count, self.aes_gcm_key)
                        self.add_server_count()
                    logger.debug(f'{self.username}: {request}')
                    self.writer.write(response)
        except Exception:
            self.died = True  # 遭遇异常退出
            logger.info(f'{self.username} 下线')
            return


PUBLIC_KEY: rsa.PublicKey
PRIVATE_KEY: rsa.PrivateKey

def set_server_keys(public_key, private_key):
    global PUBLIC_KEY
    global PRIVATE_KEY

    PUBLIC_KEY = public_key
    PRIVATE_KEY = private_key

async def new_server(reader, writer):
    global PUBLIC_KEY
    global PRIVATE_KEY

    server = Server(reader, writer, PRIVATE_KEY, PUBLIC_KEY)
    await server.start_listen()
    writer.close()
    if server.username in global_users and global_users[server.username].died:
        global_users.pop(server.username)  # 删除正常退出的用户

        for username in global_users:
            if username != server.username:
                global_users[username].push_data('offline', server.username)  # 通知其他用户


async def start_server(host, port):
    server = await asyncio.start_server(new_server, host, port)
    await server.serve_forever()
