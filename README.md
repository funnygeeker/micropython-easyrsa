[简体中文 (Chinese)](./README.ZH-CN.md)
### micropython-easyrsa
- Simple RSA encryption implementation (with limitations)
- Intended for learning purposes only, not suitable for production environment
- Currently supports encryption and decryption in Python, or encryption in Python and decryption in MicroPython

### Example Code
```python
from lib.easyrsa import EasyRSA

# Example usage
rsa = EasyRSA(256)
public_key, private_key = rsa.generate_keys()

# Save public and private keys to files
rsa.save_key_to_file(public_key, "public_key.txt")
rsa.save_key_to_file(private_key, "private_key.txt")

# Load public and private keys from files
loaded_public_key = rsa.load_key_from_file("public_key.txt")
loaded_private_key = rsa.load_key_from_file("private_key.txt")

# Encryption
message = b"Hello, World!"
ciphertext = rsa.encrypt(message, loaded_public_key)
print("Message:", message)
print("Encrypt:", ciphertext)
print('Decrypt:', rsa.decrypt(ciphertext, private_key))
```