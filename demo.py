#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
演示：512 字节头部 + 256 字节重复密钥 XOR 的「弱加密」，以及如何靠已知明文还原。
全部用合成数据，不涉及任何真实样本。
"""

import os

KEY_LEN = 256      # 密钥长度：256 字节
HEADER_LEN = 512   # 文件开头多出来的垃圾头部


# ----------------------------------------------------------------------
# 第 0 步：造一个「假 PPT」明文
# ----------------------------------------------------------------------
# 真实的老式 .ppt 是 OLE 复合文档，开头有固定的魔数和大量可预测字节，
# 其中有一段是保留区 / 填充区，内容恒为 0x00。
# 这里我们只模拟关键特征：文件最前面有一段 >=256 字节的全 0 区域。
def make_fake_ppt():
    zero_region = b"\x00" * 300                       # 开头的全 0 区域（关键！）
    body = b"This is the real PowerPoint content. " * 50  # 后面是真实内容
    return zero_region + body


# ----------------------------------------------------------------------
# 第 1 步：加密（攻击者/勒索软件那一侧做的事）
# ----------------------------------------------------------------------
def repeating_xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    junk_header = os.urandom(HEADER_LEN)   # 512 字节随机垃圾头
    cipher = repeating_xor(plaintext, key) # 正文用重复密钥异或
    return junk_header + cipher


# ----------------------------------------------------------------------
# 第 2 步：攻击（我们这一侧，不需要密码）
# ----------------------------------------------------------------------
def recover_key(blob: bytes) -> bytes:
    # (a) 跳过开头的 512 字节垃圾头，拿到真正的密文
    cipher = blob[HEADER_LEN:]

    # (b) 已知明文：开头那段本应是全 0。
    #     因为  明文(0) XOR 密钥 = 密钥，
    #     所以密文开头的字节「就是」密钥本身（相位对齐到 0）。
    #     我们直接读密文的前 256 个字节当作密钥。
    recovered = cipher[:KEY_LEN]
    return recovered


def decrypt(blob: bytes, key: bytes) -> bytes:
    cipher = blob[HEADER_LEN:]
    return repeating_xor(cipher, key)


# ----------------------------------------------------------------------
# 把整个流程走一遍
# ----------------------------------------------------------------------
def main():
    plaintext = make_fake_ppt()
    secret_key = os.urandom(KEY_LEN)          # 攻击者用的随机 256 字节密钥

    blob = encrypt(plaintext, secret_key)     # 加密后的文件
    print(f"原始明文长度        : {len(plaintext)} 字节")
    print(f"加密后文件长度      : {len(blob)} 字节  (= 512 头部 + 正文)")
    print(f"真实密钥 (前16字节) : {secret_key[:16].hex()}")

    # —— 攻击开始，我们只有 blob，没有密钥 ——
    guessed_key = recover_key(blob)
    print(f"还原密钥 (前16字节) : {guessed_key[:16].hex()}")
    print(f"密钥是否完全一致    : {guessed_key == secret_key}")

    recovered_plain = decrypt(blob, guessed_key)
    print(f"明文是否完全还原    : {recovered_plain == plaintext}")
    print(f"还原内容结尾预览    : {recovered_plain[-40:]!r}")


if __name__ == "__main__":
    main()
