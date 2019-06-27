import rsa
import json

public_key, private_key = rsa.newkeys(2048)
data = {
    'public_key': public_key.save_pkcs1().decode(),
    'private_key': private_key.save_pkcs1().decode()
}

data = json.dumps(data)
print(data)
