from classes.server import start_server, set_server_keys
import asyncio
import rsa


if __name__ == '__main__':
    with open('server_private_key', 'r') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open('server_public_key', 'r') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    set_server_keys(public_key, private_key)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_server('127.0.0.1', 9999))
