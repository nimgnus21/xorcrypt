#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xorcrypt.py —— 练手工具:512 字节头部 + 重复密钥 XOR 的弱加密与还原。

子命令:
  encrypt   给文件加密(前面加 N 字节随机头部,正文用重复密钥异或)
  decrypt   已知密钥时解密
  recover   攻击:不给密钥,靠文件里的全 0 区域自动还原密钥并解密
  showkey   只打印从文件里还原出来的密钥(十六进制)
  selftest  用合成数据自己走一遍完整流程,验证工具没问题

典型用法:
  python3 xorcrypt.py encrypt -i my.ppt -o my.enc            # 自动生成密钥 -> my.enc.key
  python3 xorcrypt.py decrypt -i my.enc -o back.ppt -k my.enc.key
  python3 xorcrypt.py recover -i my.enc -o back.ppt          # 不用密钥!
  python3 xorcrypt.py showkey -i my.enc
  python3 xorcrypt.py selftest
"""

import argparse
import os
import sys

DEF_KEYLEN = 256
DEF_HEADER = 512

# 不同文件类型开头有固定"魔数"。还原后正文若以其中之一开头,
# 基本就能确定密钥和头部长度都猜对了 —— 这就是我们的"对答案"。
KNOWN_MAGICS = [
    ("PDF",               b"%PDF"),                          # 25 50 44 46
    ("老式 Office (OLE)", bytes.fromhex("d0cf11e0a1b11ae1")),
    ("ZIP / 新版 Office", bytes.fromhex("504b0304")),        # PK\x03\x04
]


def match_magic(plaintext: bytes, expect: bytes = None):
    """返回 (类型名, 魔数) 或 None。给了 expect 就只认它。"""
    if expect is not None:
        return ("自定义前缀", expect) if plaintext[:len(expect)] == expect else None
    for name, mg in KNOWN_MAGICS:
        if plaintext[:len(mg)] == mg:
            return (name, mg)
    return None


# ------------------------- 核心原语 -------------------------
def repeating_xor(data: bytes, key: bytes) -> bytes:
    """重复密钥异或: 密文[i] = 数据[i] ^ 密钥[i mod len(key)]。加解密同一个函数。"""
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


# ------------------------- 加密 -------------------------
def do_encrypt(args):
    plaintext = open(args.input, "rb").read()

    if args.key:
        key = open(args.key, "rb").read()
        if len(key) != args.keylen:
            sys.exit(f"错误: 密钥文件应为 {args.keylen} 字节, 实际 {len(key)} 字节")
    else:
        key = os.urandom(args.keylen)          # 没给密钥就随机生成
        keypath = args.output + ".key"
        open(keypath, "wb").write(key)
        print(f"已生成随机密钥 -> {keypath}")

    header = os.urandom(args.header)           # N 字节随机垃圾头部
    blob = header + repeating_xor(plaintext, key)
    open(args.output, "wb").write(blob)
    print(f"加密完成 -> {args.output}  ({args.header} 字节头部 + {len(plaintext)} 字节正文)")


# ------------------------- 解密(已知密钥) -------------------------
def do_decrypt(args):
    blob = open(args.input, "rb").read()
    key = open(args.key, "rb").read()
    cipher = blob[args.header:]                # 切掉头部
    plaintext = repeating_xor(cipher, key)
    open(args.output, "wb").write(plaintext)
    print(f"解密完成 -> {args.output}  ({len(plaintext)} 字节)")


# ------------------------- 攻击:从全 0 区域还原密钥 -------------------------
def recover_key_from_cipher(cipher: bytes, keylen: int):
    """
    思路: 明文里一段连续的 0(或任意常量) 会让 cipher[i] == cipher[i+keylen]。
    找到最长的这种周期性区段, 就是明文的恒定区; 在该区段里
    key[off % keylen] = cipher[off], 只要区段 >= keylen 就能凑齐整把密钥。
    相位(对齐) 靠 off % keylen 自动处理, 不用手动旋转。
    返回 (key, 区段起点, 区段长度) 或 (None, 原因, None)。
    """
    n = len(cipher)
    if n < keylen:
        return None, "密文不足一个密钥周期", None

    # 找最长的「cipher[i] == cipher[i+keylen]」连续段
    best_start = best_len = 0
    cur_start = cur_len = 0
    for i in range(n - keylen):
        if cipher[i] == cipher[i + keylen]:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start = cur_len, cur_start
        else:
            cur_len = 0

    # 周期性连续段 [best_start, best_start+best_len) 对应的恒定明文区实际覆盖到 +keylen
    region_start = best_start
    region_len = best_len + keylen
    if region_len < keylen:
        return None, f"未找到>= {keylen} 字节的恒定明文区(最长 {region_len} 字节)", None

    key = bytearray(keylen)
    filled = [False] * keylen
    for off in range(region_start, region_start + region_len):
        r = off % keylen
        if not filled[r]:
            key[r] = cipher[off]
            filled[r] = True
    if not all(filled):
        return None, "相位覆盖不全, 恒定区不够长", None
    return bytes(key), region_start, region_len


def _try_one_header(blob, header, keylen):
    """用某个头部长度试一次: 返回 (key, plaintext, region_start, region_len) 或 None。"""
    if header >= len(blob):
        return None
    cipher = blob[header:]
    key, info, region_len = recover_key_from_cipher(cipher, keylen)
    if key is None:
        return None
    plaintext = repeating_xor(cipher, key)
    return key, plaintext, info, region_len


def do_recover(args):
    blob = open(args.input, "rb").read()
    expect = bytes.fromhex(args.expect) if args.expect else None

    if args.autohdr:
        # 不确定头部多长时, 挨个试常见值, 以「解密后是否以已知魔数开头」为准。
        # 只有正确的头部长度才会让正文偏移 0 对齐到真正的文件头, 魔数才对得上。
        candidates = [args.header, 0, 512, 256, 128, 1024, 2048, 768, 1536]
        seen, chosen = set(), None
        for h in candidates:
            if h in seen:
                continue
            seen.add(h)
            res = _try_one_header(blob, h, args.keylen)
            if res and match_magic(res[1], expect):
                chosen = (h,) + res
                break
        if chosen is None:
            sys.exit("自动探测失败: 试过的头部长度都没能让正文以已知魔数开头。\n"
                     "可能原因: 头部长度特殊(手动 --header)、密钥长度不是 256(--keylen)、\n"
                     "没有>= 密钥长度的连续 0 区, 或此文件不是这种加密方案。\n"
                     "建议先跑 `scan` 子命令看看情况。")
        header, key, plaintext, region_start, region_len = chosen
        hit = match_magic(plaintext, expect)
        print(f"自动探测: 头部长度 = {header} 字节 (解密后识别为 {hit[0]}, 判定正确)")
    else:
        header = args.header
        res = _try_one_header(blob, header, args.keylen)
        if res is None:
            sys.exit(f"还原失败: 头部 {header} 字节之后未找到>= {args.keylen} 字节的恒定(全0)区。"
                     "先跑 `scan` 看看。")
        key, plaintext, region_start, region_len = res

    seg = plaintext[region_start:region_start + region_len]
    zero_ratio = seg.count(0) / len(seg) if seg else 0
    hit = match_magic(plaintext, expect)

    open(args.output, "wb").write(plaintext)
    if args.keyout:
        open(args.keyout, "wb").write(key)
        print(f"还原密钥 -> {args.keyout}")
    print(f"在偏移 {region_start} 处发现 {region_len} 字节恒定区, 据此还原 {args.keylen} 字节密钥")
    print(f"恒定区解密后为 0 的比例: {zero_ratio:.1%}")
    head = plaintext[:8].hex()
    if hit:
        print(f"正文前 8 字节(hex): {head}  ->  识别为 {hit[0]} ✓, 还原正确")
    else:
        print(f"正文前 8 字节(hex): {head}  ->  未识别为已知格式; "
              "若确为某类型, 试 --autohdr 或 --header 调整, 或那段恒定区不是全 0")
    print(f"解密完成 -> {args.output}  ({len(plaintext)} 字节)")


def do_scan(args):
    """诊断: 这个文件到底能不能用这招还原? 报告最长恒定区 + 各头部长度下能否对上魔数。"""
    blob = open(args.input, "rb").read()
    expect = bytes.fromhex(args.expect) if args.expect else None
    print(f"文件大小: {len(blob)} 字节")
    print(f"文件开头 8 字节(hex): {blob[:8].hex()}  (加密状态, 一般是乱的)")
    print()

    # 1) 看正文里"周期性连续匹配"最长有多少。真·全0区会给出很长的连续匹配(几十以上);
    #    随机数据偶尔也会碰巧匹配 1~2 处, 那不是真 0 区, 不能当判据。
    body = blob[args.header:]
    _, _, rlen = recover_key_from_cipher(body, args.keylen)
    run = (rlen - args.keylen) if rlen else -1   # 连续匹配处数 = 恒定区长 - 密钥长
    if run < 0:
        verdict = "正文太短"
    elif run >= 16:
        verdict = "很可能有真正的全 0 区, 有戏 ✓"
    elif run >= 1:
        verdict = "只有零星匹配, 多半是巧合, 大概率没有可用 0 区"
    else:
        verdict = "没有周期性匹配, 没有可用 0 区"
    print(f"假设头部 {args.header} 字节时, 最长周期性连续匹配: {max(run,0)} 处  ->  {verdict}")
    print("(注意: 这只是线索。能不能还原, 以下面魔数那一栏为准。)")
    print()

    # 2) 挨个头部长度试, 看哪个能让解密结果对上已知魔数 —— 这才是最终判据
    print("头部探测(哪个长度能让正文以已知魔数开头, 命中=真的还原出来了):")
    any_hit = False
    for h in [0, 128, 256, 512, 768, 1024, 1536, 2048]:
        res = _try_one_header(blob, h, args.keylen)
        if not res:
            print(f"  头部 {h:>5}: 找不到恒定区, 无法还原")
            continue
        hit = match_magic(res[1], expect)
        tag = f"命中 {hit[0]} ✓✓✓" if hit else "无已知魔数(很可能是假密钥)"
        if hit:
            any_hit = True
        print(f"  头部 {h:>5}: 正文开头 {res[1][:4].hex()}  {tag}")
    print()
    if any_hit:
        print("结论: 能还原! 用上面命中的头部长度跑 recover --autohdr 即可。")
    else:
        print("结论: 这个文件靠单段 0 区还原不出来(没对上任何已知魔数)。\n"
              "      要么不是这种方案, 要么没有>= 密钥长度的连续 0 区 ——\n"
              "      这种就得用多段已知明文(PDF 的 %PDF-、obj、endstream 等)拼密钥, 更复杂。")


def do_showkey(args):
    blob = open(args.input, "rb").read()
    cipher = blob[args.header:]
    key, info, region_len = recover_key_from_cipher(cipher, args.keylen)
    if key is None:
        sys.exit(f"还原失败: {info}")
    print(key.hex())


# ------------------------- 自检 -------------------------
def do_selftest(args):
    keylen, header = DEF_KEYLEN, DEF_HEADER
    # 造明文: 开头 300 字节全 0 + 一段内容
    plaintext = b"\x00" * 300 + (b"hello powerpoint " * 40)
    key = os.urandom(keylen)
    blob = os.urandom(header) + repeating_xor(plaintext, key)

    rec_key, start, rlen = recover_key_from_cipher(blob[header:], keylen)
    back = repeating_xor(blob[header:], rec_key)

    print("=== selftest ===")
    print(f"明文长度        : {len(plaintext)}")
    print(f"真实密钥前8字节 : {key[:8].hex()}")
    print(f"还原密钥前8字节 : {rec_key[:8].hex()}")
    print(f"密钥一致        : {rec_key == key}")
    print(f"明文完整还原    : {back == plaintext}")
    print(f"恒定区定位      : 起点 {start}, 长度 {rlen}")
    ok = rec_key == key and back == plaintext
    print("结果            :", "通过 ✓" if ok else "失败 ✗")
    sys.exit(0 if ok else 1)


# ------------------------- 命令行 -------------------------
def main():
    ap = argparse.ArgumentParser(description="512 头部 + 重复密钥 XOR 的加密/解密/还原练手工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--keylen", type=int, default=DEF_KEYLEN, help=f"密钥长度, 默认 {DEF_KEYLEN}")
        p.add_argument("--header", type=int, default=DEF_HEADER, help=f"头部长度, 默认 {DEF_HEADER}")

    pe = sub.add_parser("encrypt", help="加密")
    pe.add_argument("-i", "--input", required=True)
    pe.add_argument("-o", "--output", required=True)
    pe.add_argument("-k", "--key", help="密钥文件(不给则随机生成并保存为 输出名.key)")
    add_common(pe); pe.set_defaults(func=do_encrypt)

    pd = sub.add_parser("decrypt", help="已知密钥解密")
    pd.add_argument("-i", "--input", required=True)
    pd.add_argument("-o", "--output", required=True)
    pd.add_argument("-k", "--key", required=True)
    add_common(pd); pd.set_defaults(func=do_decrypt)

    pr = sub.add_parser("recover", help="不用密钥, 自动还原并解密")
    pr.add_argument("-i", "--input", required=True)
    pr.add_argument("-o", "--output", required=True)
    pr.add_argument("--keyout", help="把还原出的密钥也存到这个文件")
    pr.add_argument("--autohdr", action="store_true",
                    help="不确定头部长度时, 自动试探(以能对上已知魔数为准)")
    pr.add_argument("--expect", help="自定义期望的开头(hex), 例如 PDF 用 25504446")
    add_common(pr); pr.set_defaults(func=do_recover)

    psc = sub.add_parser("scan", help="诊断: 看这个文件能否用此法还原, 以及头部多长")
    psc.add_argument("-i", "--input", required=True)
    psc.add_argument("--expect", help="自定义期望的开头(hex)")
    add_common(psc); psc.set_defaults(func=do_scan)

    ps = sub.add_parser("showkey", help="只打印还原出的密钥(hex)")
    ps.add_argument("-i", "--input", required=True)
    add_common(ps); ps.set_defaults(func=do_showkey)

    pt = sub.add_parser("selftest", help="合成数据自检")
    pt.set_defaults(func=do_selftest)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
