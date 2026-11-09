# xorcrypt

> 教学用：演示并还原一种**很弱的"加密"**——固定头部 + 重复密钥 XOR，密钥可从文件里的全 0 区直接泄露。
>
> An educational tool that demonstrates and breaks a weak "encryption" scheme (fixed header + repeating‑key XOR), where the key leaks from an all‑zero region in the plaintext — a classic known‑plaintext attack.

---

## 这是什么

有一种很弱的文件"加密"方案，长这样：

1. 在文件开头多加一段固定长度的**头部**（默认 512 字节），正常文件没有这一段。
2. 后面的正文只是用一把固定的 **256 字节密钥反复做异或（XOR）**。
3. 密钥其实藏在文件里：很多文件格式（如老式 `.ppt/.doc/.xls`）开头有一段内容**恒为全 0** 的区域。因为 `0 XOR 密钥 = 密钥`，那段 0 异或之后**直接暴露出密钥本身**，所以**不需要密码**就能还原。

这个工具把整个过程走通：加密、用密钥解密、以及**不用密钥直接还原**。

> ⚠️ 这不是真正的加密，仅用于**密码学教学**和**还原你自己的、被这种弱方案处理过的文件**。请勿用于你无权处理的文件。

---

# 🚀 新手完全指南（从零开始）

完全没用过命令行也没关系，照着下面五步做即可。

## 第 1 步：安装 Python

本工具用 Python 编写，先装好它（只需一次）。

### Windows

1. 打开 https://www.python.org/downloads/ ，点黄色大按钮下载。
2. 运行安装包。**最关键的一步**：第一个界面最下面勾上 **“Add python.exe to PATH”**，再点 **Install Now**。
3. 装完后**关掉所有命令行窗口**（没开过就跳过）。

### macOS

系统通常自带 Python 3。没有的话，从 https://www.python.org/downloads/ 下载安装即可。

### Linux

多数发行版自带。没有就：`sudo apt install python3`（Debian/Ubuntu）。

### 验证装好了没

打开命令行（见第 3 步），输入下面任意一条，能看到版本号（如 `Python 3.12.x`）就成功：

```bash
py --version
```

```bash
python3 --version
```

> 📌 **记住你用的是哪条命令**：Windows 一般是 `py`，macOS/Linux 一般是 `python3`。
> 下面所有例子都写 `python3`；**如果你在 Windows 且 `python3` 不好使，把命令里的 `python3` 全换成 `py` 即可。**

## 第 2 步：下载本工具

**方式一（简单，不用装 git）**：在本仓库页面点绿色的 **Code → Download ZIP**，下载后**解压**到一个好找的文件夹，比如桌面。

**方式二（用 git）**：

```bash
git clone https://github.com/nimgnus21/xorcrypt.git
```

---

### ⭐ 最简单的用法：双击，不用敲命令

装好 Python 后，直接**双击文件夹里的 `双击运行.bat`**，就会弹出一个菜单：

```
  1. 还原 / 解密文件   (不需要密钥，最常用)
  2. 诊断文件          (先看能不能还原)
  3. 加密文件          (练习用)
  4. 自检
  0. 退出
```

输入数字回车，再**把文件拖进窗口**即可，全程不用打命令。

- 还原结果默认**保持原文件名**，存到该文件同目录下的 **`解密结果`** 文件夹里（不会覆盖原文件）。
- 如果选 1 时发现文件本来就没加密，它会直接告诉你，并原样复制一份出来。

> 下面第 3~5 步是**命令行用法**，给想深入了解或在 Mac/Linux 上使用的人。只想图省事的话，用上面的双击菜单就够了。

---

## 第 3 步：打开命令行并进入这个文件夹

**Windows 最简单的办法**：用文件资源管理器打开解压出来的 `xorcrypt` 文件夹 → 点一下顶部的**地址栏** → 输入 `cmd` → 回车。命令行就直接停在这个文件夹里了。

**macOS**：打开“终端”，输入 `cd `（后面带个空格），把 `xorcrypt` 文件夹拖进窗口，回车。

**通用办法**：打开命令行后用 `cd` 进入文件夹：

```bash
cd 你的xorcrypt文件夹路径
```

> 怎么确认进对了？输入 `dir`（Windows）或 `ls`（Mac/Linux），应该能看到 `xorcrypt.py`。

## 第 4 步：自检，确认一切正常

```bash
python3 xorcrypt.py selftest
```

看到最后一行 **`结果 : 通过 ✓`** 就说明装好了、能用了。

## 第 5 步：动手试一次（加密 → 不用密钥还原）

先造一个练习文件（开头有一段 0，模拟被加密的老式文档）：

```bash
python3 -c "open('sample.bin','wb').write(bytes(400) + b'hello world '*50)"
```

加密它（会自动生成密钥，存成 `sample.enc.key`）：

```bash
python3 xorcrypt.py encrypt -i sample.bin -o sample.enc
```

**不用密钥**，直接破解还原：

```bash
python3 xorcrypt.py recover -i sample.enc -o sample.back --autohdr
```

验证还原的和原件完全一样：

```bash
python3 xorcrypt.py decrypt -i sample.enc -o check.bin -k sample.enc.key
```

到这里你就完整体验了一遍"不给密码也能还原"。恭喜 🎉

---

# 📖 命令详解

| 子命令 | 作用 |
|--------|------|
| `encrypt` | 给文件加密（加 N 字节随机头部 + 重复密钥 XOR） |
| `decrypt` | 已知密钥时解密 |
| `recover` | **不用密钥**，靠全 0 区自动还原密钥并解密 |
| `scan`    | 诊断：某个加密文件到底能不能被 `recover` 还原 |
| `showkey` | 只打印从文件里还原出来的密钥（十六进制） |
| `selftest`| 用合成数据自检整条链路 |

### 处理真实文件的推荐流程

**先诊断，再还原**。诊断能提前告诉你这个文件能不能成：

```bash
python3 xorcrypt.py scan -i 你的加密文件
```

看输出最后的**结论**行：
- 写着"能还原" → 跑下面的 `recover`。
- 写着"还原不出来" → 这个文件没有够长的全 0 区，这招不适用。

```bash
python3 xorcrypt.py recover -i 你的加密文件 -o 还原出来的文件 --autohdr
```

出现 `识别为 PDF/OLE/ZIP ✓, 还原正确` 就成功了。

### 常用参数

- `--autohdr`：`recover` 时自动试探头部长度（不确定头部多长就加上它）。
- `--keylen N`：密钥长度，默认 256。加密和还原两边必须一致。
- `--header N`：头部长度，默认 512。
- `--expect <hex>`：自定义"对答案"的开头字节（非常见格式时用）。
- `--keyout <file>`：把还原出的密钥也存一份。

---

# 🔍 原理与说明

## 一句话原理

异或有个性质：`0 ⊕ k = k`。凡是明文为 0 的地方，密文逐字节就等于密钥。只要文件里有一段 **≥ 密钥长度** 的连续 0，就能把整把密钥原样抄出来，再拿它异或回去就还原了全文。这类攻击叫**已知明文攻击**。

## 它怎么判断还原对不对

还原后，工具会检查正文开头是不是常见文件格式的"魔数"，对上了就说明猜对了：

| 类型 | 开头魔数（hex） | 对应扩展名 |
|------|----------------|-----------|
| PDF | `25 50 44 46` (`%PDF`) | `.pdf` |
| 老式 Office（OLE） | `d0 cf 11 e0 a1 b1 1a e1` | `.ppt` `.doc` `.xls` |
| ZIP / 新版 Office | `50 4b 03 04` (`PK..`) | `.pptx` `.docx` `.xlsx` `.zip` |

## 适用范围与局限

- **能还原的前提**：文件里存在一段 **≥ 密钥长度（默认 256 字节）的连续全 0**。老式 OLE 文档通常满足；现代压缩格式（`.pdf` 的压缩流、`.pptx`/ZIP）不一定有。
- 若没有足够长的单段 0 区，`scan` 会如实告诉你还原不出来。这类文件需要用**多段已知明文**拼密钥，本工具暂未内置。
- 本工具不处理真正的加密（如 AES）。重复密钥 XOR 不是安全加密。

## 文件说明

- `xorcrypt.py` —— 命令行工具（加密 / 解密 / 还原 / 诊断）。
- `demo.py` —— 最小化演示脚本，一次跑完"加密 → 从文件捞密钥 → 还原"，适合读代码理解原理。

## 许可证

[MIT](LICENSE) —— 仅供学习与研究使用。
