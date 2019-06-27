from struct import unpack, pack
import zlib
import json
from utils.tools import sha3_256, random_string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

cryptography_backend = default_backend()


def encrypt_aes_gcm(data, count, key):
    aes_gcm = AESGCM(key)
    return aes_gcm.encrypt(pack('>Q', count), data, None)


def decrypt_aes_gcm(data, count, key):
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(pack('>Q', count), data, None)


def encrypt_aes_cbc(data, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    iv = sha3_256(random_string().encode())[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=cryptography_backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def decrypt_aes_cbc(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=cryptography_backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(plaintext)
    unpadded_data += unpadder.finalize()
    return unpadded_data


def read_length(data):
    return unpack('>I', data)[0]


def unpack_data(data):
    #data = zlib.decompress(data)
    return json.loads(data.decode('utf-8'))


def unpack_enc_data(data, count, key):
    data = decrypt_aes_gcm(data, count, key)
    #data = zlib.decompress(data)
    return json.loads(data.decode('utf-8'))


def pack_data(data):
    data = json.dumps(data).encode()
    #data = zlib.compress(data)
    length = len(data)
    length = pack('>I', length)
    return length + data


def pack_enc_data(data, count, key):
    data = json.dumps(data).encode()
    #data = zlib.compress(data)
    data = encrypt_aes_gcm(data, count, key)
    length = len(data)
    length = pack('>I', length)
    return length + data
