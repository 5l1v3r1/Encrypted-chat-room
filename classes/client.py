from utils.protocols import *
from base64 import b64encode, b64decode
import rsa
import random
import time
from utils.tools import random_string, DH, sha3_256
import asyncio


class Client(DH):
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    server_public_key: rsa.PublicKey
    aes_gcm_key = b''
    server_count = 0
    client_count = 0

    user_dh_keys = {}
    username = ""
    handshake = False

    def __init__(self, reader, writer):
        with open('server_public_key') as f:
            self.server_public_key = rsa.PublicKey.load_pkcs1(f.read())
        self.reader = reader
        self.writer = writer

        self.client_count = random.randint(0, 18446744073709551616)
        self.server_count = random.randint(0, 18446744073709551616)

    def add_server_count(self):
        self.server_count += 1
        if self.server_count == 18446744073709551616:
            self.server_count = 0

    def add_client_count(self):
        self.client_count += 1
        if self.client_count == 18446744073709551616:
            self.client_count = 0

    async def send_handshake(self):
        client_count = rsa.encrypt(pack('>Q', self.client_count), self.server_public_key)
        server_count = rsa.encrypt(pack('>Q', self.server_count), self.server_public_key)

        dh_private = self.dh_gen_private()
        dh_public = self.dh_get_public(dh_private)

        dh_public = dh_public.to_bytes(233, 'big')
        dh_public = rsa.encrypt(dh_public, self.server_public_key)

        request = {
            'dh_public': b64encode(dh_public).decode('utf-8'),
            'client_count': b64encode(client_count).decode('utf-8'),
            'server_count': b64encode(server_count).decode('utf-8')
        }

        data = pack_data(request)
        self.writer.write(data)
        res = await self.get_response_without_enc()
        res = res['data']
        sign = b64decode(res['sign'])
        dh_other_public = b64decode(res['dh_public'])

        try:
            ret = rsa.verify(dh_other_public, sign, self.server_public_key)
            assert ret == 'SHA-512'
        except Exception:
            raise Exception('签名验证不成功, 可能为中间人攻击')

        dh_other_public = int.from_bytes(dh_other_public, 'big')
        tmp_key = self.dh_get_common_key(dh_private, dh_other_public)
        self.aes_gcm_key = sha3_256(tmp_key)

        self.handshake = True

    async def start_listen(self, callbacks):
        def handle_send_user(self, response):
            response = response['data']
            username = response['from']
            if username in self.user_dh_keys:
                iv = b64decode(response['iv'])
                ciphertext = b64decode(response['ciphertext'])
                plaintext = decrypt_aes_cbc(iv, ciphertext, self.user_dh_keys[username]['dh_common_key'])
                if 'send_user' in callbacks:
                    callbacks['send_user'](self, {
                        'type': 'send_user',
                        'data': {
                            'from': username,
                            'message': plaintext.decode()
                        }
                    })

        default_callbacks = {
            'dh_request': self.complete_dh,
            'send_user': handle_send_user
        }

        for key in callbacks:
            if key not in default_callbacks:
                default_callbacks[key] = callbacks[key]

        while True:
            length = await self.reader.readexactly(4)
            length = read_length(length)
            data = await self.reader.readexactly(length)
            response = unpack_enc_data(data, self.server_count, self.aes_gcm_key)
            self.add_server_count()
            if response['type'] in default_callbacks:
                default_callbacks[response['type']](self, response)
            else:
                pass

    async def get_response(self):
        length = await self.reader.readexactly(4)
        length = read_length(length)
        data = await self.reader.readexactly(length)
        response = unpack_enc_data(data, self.server_count, self.aes_gcm_key)
        self.add_server_count()
        return response

    async def get_response_without_enc(self):
        length = await self.reader.readexactly(4)
        length = read_length(length)
        data = await self.reader.readexactly(length)
        response = unpack_data(data)
        return response

    async def send_request_with_res(self, req_type, data={}):
        request = {}
        request['type'] = req_type
        request['data'] = data
        request['timestamp'] = time.time()
        data = pack_enc_data(request, self.client_count, self.aes_gcm_key)
        self.add_client_count()
        self.writer.write(data)
        res = await self.get_response()
        return res

    def send_request(self, req_type, data={}):
        request = {}
        request['type'] = req_type
        request['data'] = data
        request['timestamp'] = time.time()
        data = pack_enc_data(request, self.client_count, self.aes_gcm_key)
        self.add_client_count()
        self.writer.write(data)

    async def send_register(self, public_key, username):
        data = {
            'pubkey': public_key.save_pkcs1().decode(),
            'username': username
        }
        res = await self.send_request_with_res('register', data)
        return res

    async def send_login(self, private_key, username):
        res = await self.send_request_with_res('get_challenge')
        challenge = res['data']['challenge']
        sign = rsa.sign(challenge.encode(), private_key, 'SHA-512')
        data = {
            'sign': b64encode(sign).decode(),
            'username': username
        }
        res = await self.send_request_with_res('login', data)
        self.username = username
        return res

    def send_get_users(self):
        self.send_request('list')

    def send_to_user(self, username, message):
        message = message.encode()
        if username in self.user_dh_keys:
            common_key = self.user_dh_keys[username]['dh_common_key']
            iv, ciphertext = encrypt_aes_cbc(message, common_key)
            data = {
                'username': username,
                'iv': b64encode(iv).decode('utf-8'),
                'ciphertext': b64encode(ciphertext).decode('utf-8')
            }
            self.send_request('send_user', data)
            return True
        else:
            self.send_dh_request(username, True)
            return False

    def send_to_everyone(self, message):
        data = {
            'message': message
        }
        self.send_request('send_everyone', data)

    def send_dh_request(self, username, init):  # init 代表是否从 0 开始握手
        if not init:
            dh_private = self.user_dh_keys[username]['dh_private']
            dh_public = self.dh_get_public(dh_private)
            data = {
                'username': username,
                'dh_public': dh_public,
                'init': False
            }
        else:
            dh_private = self.dh_gen_private()
            dh_public = self.dh_get_public(dh_private)

            data = {
                'username': username,
                'dh_public': dh_public,
                'init': True
            }
            self.user_dh_keys[username] = {
                'dh_private': dh_private
            }
        self.send_request('dh_request', data)

    @staticmethod
    def complete_dh(self, data):
        data = data['data']
        username = data['from']
        init = data['init']
        dh_his_public = data['dh_public']

        if not init:
            dh_private = self.user_dh_keys[username]['dh_private']
            dh_common_key = self.dh_get_common_key(dh_private, dh_his_public)
            dh_common_key = sha3_256(dh_common_key)

            self.user_dh_keys[username]['dh_common_key'] = dh_common_key
            self.user_dh_keys[username]['dh_his_public'] = dh_his_public
        else:
            dh_private = self.dh_gen_private()
            dh_common_key = self.dh_get_common_key(dh_private, dh_his_public)
            dh_common_key = sha3_256(dh_common_key)

            self.user_dh_keys[username] = {
                'dh_his_public': dh_his_public,
                'dh_private': dh_private,
                'dh_common_key': dh_common_key
            }
            self.send_dh_request(username, False)


async def get_client(host, port, server_public_key):
    reader, writer = await asyncio.open_connection(host, port)

    c = Client(reader, writer)
    c.server_public_key = server_public_key
    await c.send_handshake()
    return c


async def start_listen(client: Client, callbacks):
    await client.start_listen(callbacks)


async def start_console(client: Client):
    client.send_get_users()
    client.send_to_everyone('12131231')


def test(client: Client, response):
    users = response['data']
    if len(users) > 0:
        for i in users:
            client.send_dh_request(i, True)
            global tmp_username
            tmp_username = i

tmp_username = ""

async def sendtest(client: Client):
    await asyncio.sleep(3)
    if tmp_username != "":
        print(tmp_username)
        client.send_to_user(tmp_username, b'123123')


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    task = asyncio.ensure_future(get_client('127.0.0.1', 9999))
    loop.run_until_complete(task)
    client = task.result()

    callbacks = {
        'list': test,
        'send_user': print
    }

    tasks = [start_listen(client, callbacks), start_console(client), sendtest(client)]
    loop.run_until_complete(asyncio.wait(tasks))
