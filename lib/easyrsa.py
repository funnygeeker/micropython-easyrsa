import random


class EasyRSA:
    """警告：少部分类型的信息加密后可能会失真，请在使用前进行测试"""

    def __init__(self, key_size=4096):
        """初始化RSA对象.

        Args:
            key_size (int): 密钥长度，默认为4096位.
        """
        self.key_size = key_size

    @staticmethod
    def bit_length(n):  # micropython 没有 .bit_length()
        count = 0
        while n:
            n >>= 1
            count += 1
        return count

    def generate_keys(self):
        """生成RSA公钥和私钥.

        Returns:
            tuple: 包含公钥和私钥的元组.
        """
        p = self._generate_prime()
        q = self._generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = self._generate_coprime(phi)
        d = self._mod_inverse(e, phi)
        return (n, e), (n, d)

    def encrypt(self, message, public_key):
        """使用公钥对字节串进行加密.

        Args:
            message (bytes): 需要加密的字节串.
            public_key (tuple): 公钥，包含(n, e).

        Returns:
            bytes, int: 加密后的密文，以及密文长度
        """
        n, e = public_key
        block_size = (self.bit_length(n) + 7) // 8
        # 检查消息是否过长
        if len(message) > block_size - 11:
            raise ValueError("Message is too long to encrypt with the given key size.")
        padded_blocks = [self._pad(block, block_size) for block in self._split_blocks(message, block_size)]
        ciphertext_blocks = [pow(block, e, n) for block in padded_blocks]
        ciphertext = b"".join(block.to_bytes(block_size, "big") for block in ciphertext_blocks)
        return ciphertext, len(message)

    def decrypt(self, ciphertext: tuple, private_key: tuple):
        """使用私钥对密文进行解密.

        Args:
            ciphertext (tuple): 需要解密的密文，密文长度
            private_key (tuple): 私钥，包含(n, d).

        Returns:
            bytes: 解密后的原始字节串.
        """
        n, d = private_key
        block_size = (self.bit_length(n) + 7) // 8
        ciphertext_blocks = self._split_blocks(ciphertext[0], block_size)
        padded_blocks = [pow(block, d, n) for block in ciphertext_blocks]
        message_blocks = [self._unpad(block, block_size) for block in padded_blocks]
        message = b"".join(block.to_bytes(block_size - 1, "big") for block in message_blocks)
        # message = message.lstrip(b"\x00").lstrip(b"\x01\x00\x02").lstrip(b"\0x00")

        return message[-ciphertext[1]:]

    @staticmethod
    def _split_blocks(data, block_size):
        """将数据按照指定的块大小分割成块.

        Args:
            data (bytes): 需要分割的数据.
            block_size (int): 块大小.

        Returns:
            list: 包含分割后块的列表.
        """
        return [int.from_bytes(data[i: i + block_size], "big") for i in range(0, len(data), block_size)]

    def _pad(self, block, block_size):
        """对块进行填充.

        Args:
            block (int): 块数据.
            block_size (int): 块大小.

        Returns:
            int: 填充后的块.
        """
        padding = (block_size - self.bit_length(block) // 8 - 2)
        padded_block = (1 << (padding * 8 + 16)) + (2 << (padding * 8)) + block
        return padded_block

    @staticmethod
    def _unpad(padded_message, block_size):
        """去除填充.

        Args:
            padded_message (int): 带填充的消息.
            block_size (int): 块大小.

        Returns:
            int: 去除填充后的块.
        """
        return padded_message & ((1 << (block_size * 8 - 16)) - 1)

    def _mod_inverse(self, e, phi):
        """计算模反元素.

        Args:
            e (int): 指数.
            phi (int): 欧拉函数.

        Returns:
            int: 模反元素.
        """
        x, y, gcd = self._extended_euclidean(e, phi)
        return x % phi

    @staticmethod
    def _extended_euclidean(a, b):
        """扩展欧几里得算法，计算 a 模 b 的反元素.

        Args:
            a (int): 整数 a.
            b (int): 整数 b.

        Returns:
            tuple: (x, y, gcd)，其中 x 和 y 分别为 a 和 b 的线性组合，gcd 为最大公约数.
        """
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        gcd = old_r
        x = old_s
        y = old_t
        return x, y, gcd

    @staticmethod
    def _miller_rabin_test(n, k=40):
        """执行 Miller-Rabin 素数测试.

        Args:
            n (int): 被测试的数.
            k (int): 执行测试的次数.

        Returns:
            bool: 如果 n 可能是素数，则返回 True，否则返回 False.
        """
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    def _generate_prime(self):
        """生成随机的素数.

        Returns:
            int: 生成的素数.
        """
        while True:
            num = random.getrandbits((self.key_size + 1) // 2)
            if self._miller_rabin_test(num):
                return num

    @staticmethod
    def _gcd(a, b):
        """计算a和b的最大公约数.

        Args:
            a (int): 整数a.
            b (int): 整数b.

        Returns:
            int: a和b的最大公约数.
        """
        while b != 0:
            a, b = b, a % b
        return a

    def _generate_coprime(self, phi):
        """生成与phi互质的整数.

        Args:
            phi (int): 欧拉函数phi.

        Returns:
            int: 与phi互质的整数.
        """
        while True:
            e = random.randrange(2, phi)
            if self._gcd(e, phi) == 1:
                return e

    @staticmethod
    def save_key_to_file(key, filename):
        """
        将密钥保存到文件.

        Args:
            key (tuple): 密钥，包含(n, d)或(n, e).
            filename (str): 保存密钥的文件名.
        """
        with open(filename, "wb") as f:
            f.write(b",".join(str(k).encode("utf-8") for k in key))

    @staticmethod
    def load_key_from_file(filename):
        """
        从文件加载密钥.

        Args:
            filename (str): 密钥保存的文件名.

        Returns:
            tuple: 加载的密钥，包含(n, d)或(n, e).
        """
        with open(filename, "rb") as f:
            key_data = f.read()
        key = tuple(int(k) for k in key_data.decode("utf-8").split(","))
        return key
