[English (英语)](./README.md)
### micropython-easyrsa
- （有缺陷）简单的 RSA 加密实现
- 仅用于学习用途，不适合用于生产环境
- 目前可以在 Python 上面加密和解密，或者，使用 Python 加密，在 MicroPython 上面进行解密

### 示例代码
```python
from libs.easyrsa import EasyRSA
# 示例用法
rsa = EasyRSA(256)
public_key, private_key = rsa.generate_keys()

# 保存公钥和私钥到文件
rsa.save_key_to_file(public_key, "public_key.txt")
rsa.save_key_to_file(private_key, "private_key.txt")

# 从文件加载公钥和私钥
loaded_public_key = rsa.load_key_from_file("public_key.txt")
loaded_private_key = rsa.load_key_from_file("private_key.txt")

# 加密
message = b"Hello, World!"
ciphertext = rsa.encrypt(message, loaded_public_key)
print("Message:", message)
print("Encrypt:", ciphertext)
print('Decrypt:', rsa.decrypt(ciphertext, private_key))
```