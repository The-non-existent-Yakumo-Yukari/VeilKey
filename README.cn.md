# VeilKey — DeniableMulti Web UI（N 密钥可否认加密）

> ⚠️ **概念验证（PoC）——不可用于生产。**
>
> 这是一个**研究 / 教学**性质的项目。其中的密码学实现（`crypto.js`，移植自
> Python 参考实现 `multi_key/deniable_multi.py`）**没有**经过正式验证、独立审计或密码分析。
> **请不要用它保护真实机密。** 它因多处具体限制而不适合生产使用（详见
> [SECURITY.md](SECURITY.md#6-known-limitations--attack-surface-honest-list)，中文摘要见下文）：
> HKDF 固定盐、过小的 16 位槽位空间、浏览器端 RNG 上限导致 ≥64 KiB 容器直接报错、
> 容器无完整性、以及一套尽力而为但未经验证的否认模型。这是"某一种"可否认方案的**演示**，
> **不是**经过审校的工具。
>
> English: [README.md](README.md) · 安全模型：[SECURITY.md](SECURITY.md) · 基准测试：[BENCHMARKS.md](BENCHMARKS.md)

---

这是为 N 密钥可否认方案准备的**打包桌面交付物**：运行一个 `.exe`，浏览器窗口打开，
你完全在页面内用 WebCrypto 加密 / 解密。所有密码学运算都在浏览器内完成；密钥与明文
永不离开页面。

```
webui/  （= 本仓库）
├── app.py                  # 本地启动器（纯 stdlib，无加密库）
├── app.html / app.js       # 界面—— 双语（中文 / English）
├── crypto.js               # DeniableMulti 移植到 WebCrypto（浏览器端）
├── build.py                # PyInstaller 单文件打包脚本
├── bench/                  # 性能基准（JS + Python）与图表
├── SECURITY.md             # 正式安全模型与威胁模型
├── BENCHMARKS.md           # 实测性能 / 内存，与既有方案对比的说明
└── tests/                  # pytest + Node 交叉验证 + jsdom 冒烟测试
```

## 快速开始

**双击 `dist/DeniableCipher.exe`**。浏览器标签页会打开
`http://127.0.0.1:<port>/<token>/` 网址；页面完全离线加载。通过页面内按钮关闭
（或按 Ctrl+C / 结束进程）退出。

> ⚠️ 即便它以桌面程序形式运行，请记住：这是**未经审计的 PoC 密码学代码**，
> 不是存放真实机密的安全位置。

无需安装、无需 Python、无需联网。exe 是单个文件（约 9.5 MB），不包含任何第三方
加密库——所有密码学都由浏览器内的 WebCrypto 完成。

### 浏览器页面功能

- **加密 / Encrypt** — 添加任意数量"消息 + 密钥"行；密钥在页面内按所选比特长度生成。
  可选 `pad_to`、容器 `size`、AAD。输出 Base64，可复制 / 保存。
- **解密 / Decrypt** — 粘贴 Base64 容器 + 一把密钥 → 解出对应消息。错误密钥干净地失败；
  非 UTF-8 明文退回 hex 显示。
- **规划 / Plan** — 消息长度 + `pad_to` → 最小 / 最大容器大小。
- **帮助 / Help** — 讲解每个控件作用与影响的参考页，内容与界面按钮保持同步。
- **密钥长度 / Key bits**（16 / 32 / 64 / 128 / 256 / 512）— 生成随机密钥用；记在
  `localStorage`。
- 语言切换 中/EN 记在 `localStorage`。
- **关闭服务器并退出** 按钮停止本地服务器并结束 exe。

### 密钥：任意字符串都行，长度由你决定

密钥可以是**任何非空字符串**（中文、英文、特殊字符、任意长度；其字节长度实时显示）。
有一条规则（与 Python 交叉验证过）：

> 长度**正好等于所选密钥比特数**的 hex 字符串（`bits/4` 个 hex 字符，例如 256 bit 对应
> 64 个 hex 字符）会被解码为原始字节。其余一律按 **UTF-8 字节**处理。

> ⚠️ **强度警告** — 自定义字符串密钥的强度完全取决于字符串本身；短或可预测的口令可被
> 字典攻击（GCM 的 tag 相当于一个验证预言机）。正式用途请优先使用生成的随机密钥。

---

## 安全模型——诚实的摘要

完整说明见 **[SECURITY.md](SECURITY.md)**（英文）。请务必阅读；以下是要点：

- **计算安全，而非信息论安全。** 安全性建立在 AES-256-GCM 与 HKDF-SHA256 之上
  （标准假设），只针对**概率多项式时间（PPT）敌手**成立。
- **胁迫者模型（承重假设）。** 抗性依赖于一个假设：胁迫者是 PPT、诚实但好奇的胁迫者，
  只能强迫你交出密钥的**真子集**，**无法一次逼出全部 N 把密钥**，也无法预知隐藏内容。
  如果它能夺走**全部**密钥，**一切都会失守**。
- **N 密钥的目标 = 否认完整性，而非否认存在。** 你可以承认有多个槽：每个槽的位置只由
  自己的密钥推出，所以只拿着你交出的那部分密钥的胁迫者，**数不清还剩多少槽、判断不出你
  真正要保留哪条、也无法核实你是否交全了**。
- **诚实的限制：** 容器*大小*会泄露量级；只有槽本身被认证（槽之间填充无完整性）；
  且这是 PoC。

### 中文要点：威胁模型一句话

> 只扛得住"**只能逼你交出部分密钥**"的诚实但好奇胁迫者；扛不住"**能夺走全部密钥**"的
> 胁迫者，也扛不住想要**否认任何隐藏内容存在**的模型。本方案承认存在、否认完整。

---

## 性能与内存

可复现的实测数字（JS WebCrypto 构建 + Python 参考实现）：**[BENCHMARKS.md](BENCHMARKS.md)**。

主要结论（指示性数字，详见文档）：

- **加密大致随槽数线性增长**（每个槽一次 HKDF + 一次 AES-GCM）：
  JS 0.5 ms（1 槽）→ 8.4 ms（32 槽）。
- **解密与槽数基本无关**——每把密钥自行定位自己的槽（JS 约 0.3–0.9 ms，
  与 N 无关）。这是"密钥自定位"架构的核心优势。
- **错误密钥解密**最多做 τ=32 次 GCM 验证（DoS 上界；Python 约 0.2–0.5 ms）。
- **密钥长度（16…512 bit）成本基本为零**——HKDF 把任意长度密钥归一化为 32 字节的
  加密密钥，所以比特选择影响的是密钥*熵 / 解析规则*，而不是速度。

  对应你的问题"速度 / 内存如何随密文长度与密钥长度变化"：
  **密文长度**主要随消息条数变（加密线性、解密持平）；**密钥长度**对速度与内存都几乎
  无影响；JS 单次操作的堆增量约 0–1 MiB（含 GC 噪声）。

关于既有方案的对比说明：CDNR97 一类的构造是**逐比特**扩展、伪装需要**额外通信轮次**；
本方案用**每次一条消息一次 AES-GCM + 一次 HKDF** 封装，伪装只需**一轮**（交出密钥真子集）。
我们不声称与同行评审方案具备同等*形式化安全*——详见 BENCHMARKS.md。"StegoED" 无法定位
为一个明确的已发表方案，因此**不给出编造的对比数字**。

---

## 从源码运行（开发）

```bash
# 在 webui/ 目录下——无需额外安装（纯 stdlib）
python app.py
```

可用 `DC_TOKEN` / `DC_PORT` / `DC_NO_OPEN` 环境变量固定 token/端口或禁止自动打开浏览器
（供自动化测试使用）。

## 打包 exe

```bash
pip install pyinstaller -i https://pypi.org/simple   # 若未安装
python build.py                                      # → dist/DeniableCipher.exe
```

因为 `app.py` 是纯 stdlib，PyInstaller 不打包任何第三方加密钩子；exe 只含 Python stdlib
加 `app.html`、`app.js`、`crypto.js`（通过 `--add-data`）。`resource_path()` 在冻结状态下
从 `sys._MEIPASS` 解析，否则从脚本目录解析。

打包选项：`--dir`（onedir）、`--console`（保留控制台窗口）、`--name`。

## 复现基准测试

```bash
node bench/bench.js bench/bench-results.json                  # JS/WebCrypto 构建
PYTHONPATH="<含 deniable_core 的父项目>" python bench/bench_py.py bench/bench-py-results.json
python bench/make_charts.py                                   # 表格 + PNG 图表
```

具体场景与读法见 [BENCHMARKS.md](BENCHMARKS.md)。

## 测试

```bash
# 在仓库根目录
pytest                                          # 全部套件
```

> 交叉兼容套件（`test_cross_compat.py`）在**字节级**上比较 JS WebCrypto 移植与 **Python
> 参考实现**；后者位于完整的 `DeniableCipher` 项目（含 `deniable_core.py` 与 `multi_key/`
> 的目录），不在这个独立的 webui 包中。缺失参考实现（或 Node）时该套件会整体跳过。要真正
> 运行它，请把参考实现放到 `PYTHONPATH`：
>
> ```bash
> PYTHONPATH="C:/path/to/DeniableCipher-main" pytest tests/test_cross_compat.py -v
> ```

- `tests/test_cross_compat.py` — 字节级交叉验证（HKDF、槽位、裸 AES-GCM、双向完整往返），
  含任意 UTF-8 字符串密钥与 hex 解析规则。需要 Node + Python 参考实现。
- `tests/test_server.py` — 启动器安全姿态（token 门禁、CSP/no-store、路径穿越、关闭）
  + 真实的子进程生命周期测试。
- `tests/ui_smoke.js` — 用 jsdom 驱动真实页面的冒烟测试（加密/解密、错误密钥失败、
  中文串密钥往返、规划、语言切换、增删行）。需要 `jsdom`；缺失时优雅跳过。

## 疑难排查

- **exe 启动后没打开页面** — 查看 exe 旁的 `deniable_error.log`（`--noconsole` 构建没有终端）。
- **没有默认浏览器** — 开发模式下手动打开打印出的 URL。
- **端口被占用** — exe 始终绑定临时端口（0）或你的 `DC_PORT`，一般不会冲突。

## 许可证

MIT（与父项目 `DeniableCipher` 一致）。
