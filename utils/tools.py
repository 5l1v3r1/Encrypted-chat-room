import rsa
import hashlib
import random
import string

def vaild_public_key(key):
    try:
        rsa.PublicKey.load_pkcs1(key)
    except Exception:
        return False
    return True


def verify_username(username):
    if len(username) > 64:
        return False
    if len(username) < 4:
        return False
    if '<' in username or '>' in username:
        return False
    return True


def sha3_256(string):
    if 'encode' in dir(string):
        return hashlib.sha3_256(string.encode()).hexdigest()
    else:
        return hashlib.sha3_256(string).digest()


def random_string():
    return "".join(random.choices(string.ascii_letters, k=16))


class DH():
    DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    DH_GENERATOR = 2

    def dh_gen_private(self):
        return random.randint(0, self.DH_PRIME)

    def dh_get_public(self, private):
        return pow(self.DH_GENERATOR, private, self.DH_PRIME)

    def dh_get_common_key(self, private, other_public):
        key = pow(other_public, private, self.DH_PRIME)
        return int.to_bytes(key, 256, 'big')
