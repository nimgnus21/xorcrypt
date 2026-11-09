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


def recover_core(blob, keylen, header, autohdr, expect):
    """
    还原核心。成功返回 dict(header, key, plaintext, region_start, region_len, hit)，
    失败返回 (None, 原因字符串)。供命令行 do_recover 和交互菜单共用。
    """
    if autohdr:
        # 不确定头部多长时, 挨个试常见值, 以「解密后是否以已知魔数开头」为准。
        candidates = [header, 0, 512, 256, 128, 1024, 2048, 768, 1536]
        seen = set()
        for h in candidates:
            if h in seen:
                continue
            seen.add(h)
            res = _try_one_header(blob, h, keylen)
            if res and match_magic(res[1], expect):
                key, plaintext, region_start, region_len = res
                return dict(header=h, key=key, plaintext=plaintext,
                            region_start=region_start, region_len=region_len,
                            hit=match_magic(plaintext, expect)), None
        return None, "试过的头部长度都没能让正文以已知魔数开头"
    else:
        res = _try_one_header(blob, header, keylen)
        if res is None:
            return None, f"头部 {header} 字节之后未找到 >= {keylen} 字节的恒定(全0)区"
        key, plaintext, region_start, region_len = res
        return dict(header=header, key=key, plaintext=plaintext,
                    region_start=region_start, region_len=region_len,
                    hit=match_magic(plaintext, expect)), None


def do_recover(args):
    blob = open(args.input, "rb").read()
    expect = bytes.fromhex(args.expect) if args.expect else None

    r, err = recover_core(blob, args.keylen, args.header, args.autohdr, expect)
    if r is None:
        sys.exit(f"还原失败: {err}。\n"
                 "可能原因: 头部长度特殊(--header)、密钥长度不是 256(--keylen)、\n"
                 "没有足够长的连续 0 区, 或此文件不是这种加密方案。先跑 `scan` 看看。")
    header, key, plaintext = r["header"], r["key"], r["plaintext"]
    region_start, region_len, hit = r["region_start"], r["region_len"], r["hit"]
    if args.autohdr and hit:
        print(f"自动探测: 头部长度 = {header} 字节 (解密后识别为 {hit[0]}, 判定正确)")

    seg = plaintext[region_start:region_start + region_len]
    zero_ratio = seg.count(0) / len(seg) if seg else 0

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

    # 先看文件"原样"开头是不是已知格式的魔数。是的话, 它本来就是正常文件, 没加密,
    # 根本不用还原 —— 避免对着一个好文件瞎解。
    raw = match_magic(blob, expect)
    if raw:
        print(f"文件开头 8 字节(hex): {blob[:8].hex()}  =  {blob[:8].decode('latin1')!r}")
        print()
        print(f"⚠️  这个文件开头本身就是 {raw[0]} 的标志 —— 它【没有被加密】, 就是一个正常文件。")
        print(f"    直接把扩展名改对、双击打开即可, 不需要 recover。")
        print(f"    (如果它打不开, 那是文件损坏之类的问题, 和这种 XOR 弱加密无关。)")
        return
    print(f"文件开头 8 字节(hex): {blob[:8].hex()}  (未识别为已知格式, 可能是被加密/打乱的)")
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


# ------------------------- 交互菜单(双击 / 无参数运行) -------------------------
def _ask_path(prompt):
    """读入一个文件路径。支持把文件拖进窗口(会自动去掉首尾引号)。"""
    return input(prompt).strip().strip('"').strip("'").strip()


def _default_decrypt_output(inp):
    """解密输出默认：保持原文件名，放到同目录下的「解密结果」子文件夹，避免覆盖原文件。"""
    p = os.path.abspath(inp)
    outdir = os.path.join(os.path.dirname(p), "解密结果")
    os.makedirs(outdir, exist_ok=True)
    return os.path.join(outdir, os.path.basename(p))   # 原文件名


def _run(fn, **kw):
    """调用一个 do_* 函数，并把它的 sys.exit / 异常转成友好提示，不中断菜单。"""
    try:
        fn(argparse.Namespace(**kw))
    except SystemExit as e:
        if e.code not in (0, None):
            print("\n⚠️  " + str(e.code))
    except FileNotFoundError:
        print("\n⚠️  找不到这个文件，检查路径对不对（可以直接把文件拖进窗口）。")
    except Exception as e:
        print("\n⚠️  出错了：", e)


def _menu_recover(inp):
    """菜单里的「还原」处理，给出清晰、不矛盾的结论。"""
    try:
        blob = open(inp, "rb").read()
    except FileNotFoundError:
        print("\n⚠️  找不到这个文件，检查路径对不对（可以直接把文件拖进窗口）。")
        return
    except Exception as e:
        print("\n⚠️  打不开这个文件：", e)
        return

    out = _default_decrypt_output(inp)
    raw = match_magic(blob)

    # 情况 A：文件开头本来就是正常格式 —— 没被这种 XOR 加密，不用还原
    if raw:
        import shutil
        shutil.copy(inp, out)
        print(f"\n✅ 已处理完成，文件可用。")
        print(f"   它开头已经是正常的 {raw[0]} 格式，说明【没有被这种 XOR 方式加密】、不需要还原。")
        print(f"   已把它(保持原文件名)放到：\n   {out}")
        print(f"   → 直接双击打开即可。")
        print(f"   (若它其实打不开，可能只加密了一部分或文件损坏，选【2 诊断】再看看。)")
        return

    # 情况 B：开头是乱的 —— 尝试无密钥还原
    print("\n正在尝试还原(无需密钥)...")
    r, err = recover_core(blob, DEF_KEYLEN, DEF_HEADER, True, None)
    if r is None:
        # 情况 C：没解出来
        print(f"\n⚠️  没能自动还原：{err}。")
        print(f"   它可能不是这种 XOR 加密方式，或没有足够长的连续 0 区。")
        print(f"   建议选【2 诊断】看看具体情况。")
        return

    open(out, "wb").write(r["plaintext"])
    t = r["hit"][0] if r["hit"] else "未知类型"
    print(f"\n✅ 解密成功！识别为 {t}。")
    print(f"   已保存(保持原文件名)到：\n   {out}")
    print(f"   (头部长度 {r['header']} 字节，还原出 {DEF_KEYLEN} 字节密钥。) → 去打开试试。")


def interactive_menu():
    while True:
        print()
        print("=" * 46)
        print("   xorcrypt  弱加密(重复密钥 XOR)还原工具")
        print("=" * 46)
        print("  1. 还原 / 解密文件   (不需要密钥，最常用)")
        print("  2. 诊断文件          (先看能不能还原)")
        print("  3. 加密文件          (练习用)")
        print("  4. 自检")
        print("  0. 退出")
        choice = input("\n请输入数字再回车 [默认 1]: ").strip() or "1"

        if choice == "0":
            print("再见。")
            return

        elif choice == "1":
            inp = _ask_path("\n把要还原的文件拖进窗口再回车：\n> ")
            if not inp:
                continue
            _menu_recover(inp)

        elif choice == "2":
            inp = _ask_path("\n把要诊断的文件拖进窗口再回车：\n> ")
            if not inp:
                continue
            print()
            _run(do_scan, input=inp, expect=None, keylen=DEF_KEYLEN, header=DEF_HEADER)

        elif choice == "3":
            inp = _ask_path("\n把要加密的文件拖进窗口再回车：\n> ")
            if not inp:
                continue
            out = inp + ".enc"
            print()
            _run(do_encrypt, input=inp, output=out, key=None,
                 keylen=DEF_KEYLEN, header=DEF_HEADER)

        elif choice == "4":
            print()
            _run(do_selftest)

        else:
            print("没听懂，请输入 0 / 1 / 2 / 3 / 4。")
            continue

        input("\n按回车回菜单...")


# ------------------------- 命令行 -------------------------
def main():
    # 无参数(例如双击、或直接 py xorcrypt.py)就进入交互菜单
    if len(sys.argv) == 1:
        interactive_menu()
        return
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
