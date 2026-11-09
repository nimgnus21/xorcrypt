# xorcrypt

> 教学用：演示并还原一种**很弱的"加密"**——固定头部 + 重复密钥 XOR，密钥可从文件里的全 0 区直接泄露。
>
> An educational tool that demonstrates and breaks a weak "encryption" scheme: a fixed header prepended to a file plus a repeating‑key XOR, where the key leaks from an all‑zero region in the plaintext (a classic known‑plaintext attack).

---

## 这是什么

有一种很弱的文件"加密"方案，长这样：

1. 在文件开头多加一段固定长度的**头部**（默认 512 字节），正常文件没有这一段。
2. 后面的正文只是用一把固定的 **256 字节密钥反复做异或（XOR）**。
3. 密钥其实藏在文件里：很多文件格式（如老式 `.ppt/.doc/.xls` 的 OLE 结构）开头有一段内容**恒为全 0** 的区域。因为 `0 XOR 密钥 = 密钥`，那段 0 异或之后**直接暴露出密钥本身**，所以**不需要密码**就能还原。

这个仓库用一个命令行工具把整个过程走通：加密、用密钥解密、以及**不用密钥直接还原**（即对重复密钥 XOR 的**已知明文攻击**）。

> ⚠️ 这不是真正的加密。重复密钥 XOR 属于古典密码里最脆弱的一类，本工具仅用于**密码学教学**和**还原你自己的、被这种弱方案处理过的文件**。请勿用于你无权处理的文件。

## 原理一句话

异或有个性质：`0 ⊕ k = k`。凡是明文为 0 的地方，密文逐字节就等于密钥。只要文件里有一段 **≥ 密钥长度** 的连续 0，就能把整把密钥原样抄出来，再拿它异或回去即可还原全文。

## 环境要求

- Python 3.7+（只用标准库，无需安装任何依赖）
- Windows 上命令一般是 `py`，macOS / Linux 上一般是 `python3`

## 快速开始

先自检，确认环境正常：

```bash
python3 xorcrypt.py selftest
```

### 子命令一览

| 子命令 | 作用 |
|--------|------|
| `encrypt` | 给文件加密（加 N 字节随机头部 + 重复密钥 XOR） |
| `decrypt` | 已知密钥时解密 |
| `recover` | **不用密钥**，靠全 0 区自动还原密钥并解密 |
| `scan`    | 诊断：某个加密文件到底能不能被 `recover` 还原 |
| `showkey` | 只打印从文件里还原出来的密钥（十六进制） |
| `selftest`| 用合成数据自检整条链路 |

### 典型用法

加密（不给密钥就随机生成，保存为 `输出名.key`）：

```bash
python3 xorcrypt.py encrypt -i secret.ppt -o secret.enc
```

已知密钥解密：

```bash
python3 xorcrypt.py decrypt -i secret.enc -o back.ppt -k secret.enc.key
```

**不用密钥还原**（头部长度也让它自动探测）：

```bash
python3 xorcrypt.py recover -i secret.enc -o back.ppt --autohdr
```

处理真实文件前，**先诊断**能不能还原：

```bash
python3 xorcrypt.py scan -i secret.enc
```

看输出最后的**结论**行即可。

## 它怎么判断还原对不对

还原后，工具会检查正文开头是不是常见文件格式的"魔数"，对上了就说明密钥和头部都猜对了：

| 类型 | 开头魔数（hex） | 对应扩展名 |
|------|----------------|-----------|
| PDF | `25 50 44 46` (`%PDF`) | `.pdf` |
| 老式 Office（OLE） | `d0 cf 11 e0 a1 b1 1a e1` | `.ppt` `.doc` `.xls` |
| ZIP / 新版 Office | `50 4b 03 04` (`PK..`) | `.pptx` `.docx` `.xlsx` `.zip` |

其它格式可以用 `--expect <hex>` 自定义期望的开头。

## 参数

- `--keylen N`：密钥长度，默认 256。加密和还原两边必须一致。
- `--header N`：头部长度，默认 512。
- `--autohdr`：`recover` 时自动试探头部长度（以能对上已知魔数为准）。
- `--expect <hex>`：自定义"对答案"的开头字节，例如 PDF 用 `25504446`。
- `--keyout <file>`：把还原出的密钥也存一份。

## 适用范围与局限

- **能还原的前提**：文件里存在一段 **≥ 密钥长度（默认 256 字节）的连续 0**，且其中确实是全 0（而非其它常量）。老式 OLE 文档通常满足；现代压缩格式（`.pdf` 的 FlateDecode 流、`.pptx`/ZIP）不一定有这么长的 0 区。
- 若没有足够长的单段 0 区，`scan` 会如实告诉你还原不出来。这类文件需要用**多段已知明文**（如 PDF 的 `%PDF-`、`obj`、`endstream` 等固定字样）拼出密钥，本工具暂未内置。
- 本工具不处理真正的加密（AES 等）。重复密钥 XOR 不是安全加密。

## 文件说明

- `xorcrypt.py` —— 命令行工具（加密 / 解密 / 还原 / 诊断）。
- `demo.py` —— 最小化演示脚本，一次性跑完"加密 → 从文件捞密钥 → 还原"，适合读代码理解原理。

## 许可证

[MIT](LICENSE) —— 仅供学习与研究使用。
