# coding=utf-8
# Author: gdream@126.com
# Timer: 2020/1/11 16:01

"""
✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒

		*✎  数据编码方式（数据传输）： Base64 和 Hex  。（ 二次封装的四个接口：base64_encode、base64_decode、str_to_hex 和 hex_to_str ）

		*✎  加解密 和 签名验签 方式 ： RSA 、 AES(MOOD_CBC) 、 ECC 。

✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒
✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒✒
"""

from base64 import b64encode, b64decode
from binascii import b2a_hex, a2b_hex

from Crypto import Random
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Signature import PKCS1_v1_5 as sign_pk

# from py_ecc import
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key, generate_key


def base64_encode(text: str) -> str:
    return b64encode(text.encode("utf-8")).decode("utf-8")


def base64_decode(text: str) -> str:
    return b64decode(text.encode("utf-8")).decode("utf-8")


def str_to_hex(text: str) -> str:
    return b2a_hex(text.encode("utf-8")).decode("utf-8")


def hex_to_str(text: str) -> str:
    return a2b_hex(text.encode("utf-8")).decode("utf-8")


def rsa_pem_generate(length: int) -> tuple:
    """
    随机生成RSA公私钥对
    :param length: 秘钥位数
    :return: pem格式公私钥对 (前公钥后私钥)
    """
    gen = Random.new().read
    rsa = RSA.generate(length, gen)

    private_pem = rsa.exportKey().decode("utf-8")
    public_pem = rsa.publickey().exportKey().decode("utf-8")

    return public_pem, private_pem


def rsa_encrypt(plain_text: str, public_pem_str: str) -> bytes:
    """
    RSA公钥加密
    :param plain_text: 明文
    :param public_pem_str: 公钥
    :return: 二进制的密文
    """
    publicKey = RSA.importKey(public_pem_str)
    pk = PKCS1_v1_5.new(publicKey)

    cipher_text = pk.encrypt(plain_text.encode("utf-8"))

    return cipher_text


def rsa_decrypt(cipher_text: bytes, private_pem_str: str) -> str:
    """
    RSA私钥解密
    :param cipher_text: 二进制的密文
    :param private_pem_str: 私钥
    :return: 明文
    """
    privateKey = RSA.importKey(private_pem_str)
    pk = PKCS1_v1_5.new(privateKey)

    plain_text = pk.decrypt(cipher_text, "error").decode("utf-8")

    return plain_text


def rsa_sign_gen(text: str, hash_algorithm, private_pem_str: str) -> bytes:
    """
    RSA私钥签名
    :param text: 消息内容
    :param hash_algorithm: 哈希算法 (type: function)
    :param private_pem_str: 私钥
    :return: 二进制的签名
    """
    privateKey = RSA.importKey(private_pem_str)
    data = hash_algorithm.new(text.encode("utf-8"))

    pk = sign_pk.new(privateKey)
    signature = pk.sign(data)

    return signature


def rsa_sign_verify(text: str, hash_algorithm, public_pem_str: str, signature: bytes) -> bool:
    """
    RSA公钥验签
    :param text: 消息内容
    :param hash_algorithm: 哈希算法 (type: function)
    :param public_pem_str: 公钥
    :param signature: 二进制的签名
    :return: True or False
    """
    publicKey = RSA.importKey(public_pem_str)
    data = hash_algorithm.new(text.encode("utf-8"))

    pk = sign_pk.new(publicKey)
    # pk.verify(data, signature)

    return pk.verify(data, signature)


def to_16bits(text: str) -> bytes:
    """
    将明文输出成以16为倍数的二进制数
    :param text: 明文
    :return: 以16为倍数的二进制数
    """
    b_text = text.encode("utf-8")
    remainder = len(b_text) % 16
    if remainder != 0:
        b_text += b'\x00' * (16-remainder)

    return b_text


def aes_encrypt(plain_text: str, secret_key: str, iv: str) -> bytes:
    """
    AES加密。CBC模式
    :param plain_text: 明文
    :param secret_key: 秘钥
    :param iv: 向量
    :return: 二进制的密文
    """
    aes = AES.new(to_16bits(secret_key), AES.MODE_CBC, to_16bits(iv))
    cipher_text = aes.encrypt(to_16bits(plain_text))

    return cipher_text


def aes_decrypt(cipher_text: bytes, secret_key: str, iv: str) -> str:
    """
    AES解密。CBC模式
    :param cipher_text: 二进制的密文
    :param secret_key: 秘钥
    :param iv: 向量
    :return: 明文
    """
    aes = AES.new(to_16bits(secret_key), AES.MODE_CBC, to_16bits(iv))
    plain_text = aes.decrypt(cipher_text).decode("utf-8").rstrip("\0")

    return plain_text


def ecc_pem_generate(length: int) -> tuple:
    ecc = ECC.generate(curve=f"P-{length}")

    private_pem = ecc.export_key(format="PEM")
    public_pem = ecc.public_key().export_key(format="PEM")

    return public_pem, private_pem


def ecc_generate() -> tuple:
    eth_k = generate_eth_key()
    sk_hex = eth_k.to_hex()
    pk_hex = eth_k.public_key.to_hex()

    return pk_hex, sk_hex

    # secp_k = generate_key()
    # sk_bytes = secp_k.secret  # bytes
    # pk_bytes = secp_k.public_key.format(True)  # bytes
    # print(sk_bytes)


def ecc_encrypt(plain_text: str, public_pk: hex or bytes) -> bytes:
    return encrypt(public_pk, plain_text.encode("utf-8"))


def ecc_decrypt(cipher_text: bytes, private_pk: hex or bytes) -> bytes:
    return decrypt(private_pk, cipher_text)


def ecc_sign_gen():
    pass
# https://pypi.org/project/eciespy/


if __name__ == "__main__":
    key = """-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKyELDf9bITX3yn0
BnpYpMnGfpB55S0fTWOn4Ufa1AHYLJJ5q71VrvQOyXXwzbqlfocd5YaV+pLCj4Ss
6b2zPhSLVgwxSr9WcdlL9Y9FNJacHpWwMCcenGOvLM/w0Wznv3fFd1AQDgF9zR6m
pmiWSlQd+6uj/mX0PAlwRROxnMofAgMBAAECgYBvPDYK0AP1z/9b3LWEk72FQNCA
tagYpRNQS4INw8JpggqTU5Jx3VqWkSZDPsZYL7daxeMmGXRcxsilQpzgLT+8DmFh
Cf14CLijfUN88T8RjhPgg4jOEdhUYMRmhpHZET2TsTy1u0eO4b/n3Oijz4eCWtX7
UAq5uIaLocHbsbUj8QJBANYXiP9lqIQ9U/GYtEeiL9HjifMpVC7jhZ5bBXjfo6g4
ManEtBJ33BMC4aqHlYi/N9RJUrZxpzO15UT3zenuMikCQQDOSTiFCke0DLF4Gjbe
y9u/gUyA9svklCjfEje9aUYIpMDZCYg5C7Eawb88kGw+qT0MYUIFmCwZt38IpWqL
KXMHAkB6J/+hSk329k85YNosrVv/tIb32bMQ9f09t83NhD2LNFUR+wyMJRvLNS+x
757g4cpnNFcfhoXSuYzR51r0iVbRAkBd5MoLFEDK3TQyHIx5IIUnR60QzkTECAQK
dPpWBoLQEF2O7F3KyV2VdjabVIlQhCu7ZNFuRnNcST9TKieyq+0lAkArk4V7KMLm
O1XN1cvjs3y2cmVMmN2iPO9rE0W6xBNorQVtu84SUJBUogdoXG1EXMOn0udnSNsL
RKd9lXUlUVIT
-----END PRIVATE KEY-----
"""
    import hashlib
    print(hashlib.md5("我喜欢你".encode("utf-8")).hexdigest())


