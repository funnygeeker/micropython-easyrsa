from lib.easyrsa import EasyRSA
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
