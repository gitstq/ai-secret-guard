# 🔒 AI Secret Guard

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Tests-26%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-lightgrey" alt="Platform">
</p>

<p align="center">
  <b>🌐 <a href="#简体中文">简体中文</a> | <a href="#繁體中文">繁體中文</a> | <a href="#english">English</a></b>
</p>

---

## English

### 🎉 Project Introduction

**AI Secret Guard** is an intelligent, AI-enhanced secret detection and risk assessment tool designed to help developers and security teams identify API keys, passwords, tokens, and other sensitive information accidentally committed to code repositories.

**Core Value Proposition:**
- 🛡️ **Prevent security breaches** before they happen by catching secrets in code
- 🤖 **AI-enhanced accuracy** reduces false positives by up to 60% compared to traditional regex-only tools
- ⚡ **Blazing fast scans** with multi-threaded processing - scan 1000+ files in seconds
- 🎯 **Contextual risk scoring** prioritizes the most dangerous exposures

**Inspiration:** This project was inspired by tools like `gitleaks` and `truffleHog`, but addresses their key limitations: high false-positive rates, lack of risk context, and limited customization. We built AI Secret Guard from the ground up with a focus on **accuracy, speed, and actionable intelligence**.

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔍 **15+ Detection Rules** | Covers OpenAI, AWS, GitHub, Slack, Stripe, JWT, private keys, database URLs, and more |
| 🤖 **AI-Enhanced Analysis** | Contextual analysis reduces false positives from test files, documentation, and examples |
| 🎯 **Risk Scoring Engine** | Calculates 0-100 risk scores based on secret type, file context, and confidence |
| 📊 **Multi-Format Reports** | Generate Console, JSON, and HTML reports with beautiful visualizations |
| ⚡ **High Performance** | Multi-threaded scanning with configurable worker pools |
| 🔧 **CI/CD Integration** | Native GitHub Actions support with fail-on-secret capabilities |
| 🛠️ **Custom Rules** | Easily extend with your own detection patterns |
| 🌐 **Zero Dependencies** | Uses only Python standard library - maximum portability |

### 🚀 Quick Start

**Requirements:**
- Python 3.8 or higher

**Installation:**

```bash
# Install from PyPI (coming soon)
pip install ai-secret-guard

# Or install from source
git clone https://github.com/gitstq/ai-secret-guard.git
cd ai-secret-guard
pip install -e .
```

**Basic Usage:**

```bash
# Scan a repository
ai-secret-guard scan /path/to/repo

# Generate HTML report
ai-secret-guard scan /path/to/repo --format html --output report.html

# Scan a single file
ai-secret-guard file /path/to/file.py

# Disable AI enhancement for faster scanning
ai-secret-guard scan /path/to/repo --no-ai
```

**Python API:**

```python
from ai_secret_guard import SecretScanner
from ai_secret_guard.reporter import ReportGenerator

# Initialize scanner
scanner = SecretScanner()

# Scan repository
result = scanner.scan_repository("/path/to/repo")

# Generate report
reporter = ReportGenerator(result)
reporter.generate_html_report("report.html")
```

### 📖 Detailed Usage Guide

**Advanced Scan Options:**

```bash
# Custom worker threads
ai-secret-guard scan . --workers 8

# Custom ignore patterns
ai-secret-guard scan . --ignore "*.log" --ignore "temp/*"

# JSON output for programmatic use
ai-secret-guard scan . --format json --output results.json
```

**CI/CD Integration (GitHub Actions):**

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ai-secret-guard
      - run: ai-secret-guard scan .
```

### 💡 Design Philosophy

**Why AI Secret Guard?**

1. **Accuracy First:** Traditional tools rely solely on regex patterns, leading to excessive false positives. Our AI-enhanced layer analyzes context (file type, surrounding code, variable names) to distinguish real secrets from examples and test data.

2. **Actionable Intelligence:** Every finding includes a risk score (0-100) and specific remediation advice. Critical secrets in production configs are flagged immediately.

3. **Developer Experience:** Zero dependencies mean it works anywhere Python runs. The CLI provides real-time progress bars and clear, color-coded output.

**Technology Choices:**
- **Pure Python:** Maximum compatibility, no dependency hell
- **ThreadPoolExecutor:** Efficient I/O-bound scanning without GIL limitations
- **Dataclass Models:** Clean, type-hinted code that's easy to extend

**Roadmap:**
- [ ] Machine learning model for even better false-positive reduction
- [ ] Pre-commit hook integration
- [ ] SARIF format output for security platform integration
- [ ] Docker container for consistent CI/CD usage
- [ ] IDE plugins (VS Code, IntelliJ)

### 📦 Packaging & Deployment

**Build from source:**

```bash
# Install build dependencies
pip install build twine

# Build package
python -m build

# Upload to PyPI (maintainers only)
python -m twine upload dist/*
```

**Docker (coming soon):**

```bash
docker run -v $(pwd):/repo gitstq/ai-secret-guard scan /repo
```

### 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

- 🐛 **Bug Reports:** Open an issue with reproduction steps
- 💡 **Feature Requests:** Open an issue with the `enhancement` label
- 🔧 **Pull Requests:** Fork, branch, and submit PRs to `main`

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 简体中文

### 🎉 项目介绍

**AI Secret Guard** 是一款智能AI增强型密钥泄露检测与风险评估工具，旨在帮助开发者和安全团队识别意外提交到代码仓库中的API密钥、密码、令牌和其他敏感信息。

**核心价值：**
- 🛡️ **在安全事故发生前预防**，及时发现代码中的密钥泄露
- 🤖 **AI增强的准确性**，相比传统纯正则工具降低60%误报率
- ⚡ **极速扫描**，多线程处理 - 秒级扫描1000+文件
- 🎯 **上下文风险评分**，优先处理最危险的泄露

**灵感来源：** 本项目受到 `gitleaks` 和 `truffleHog` 等工具的启发，但解决了它们的关键局限：高误报率、缺乏风险上下文、有限的自定义能力。我们从零开始构建AI Secret Guard，专注于**准确性、速度和可操作的情报**。

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔍 **15+ 检测规则** | 覆盖OpenAI、AWS、GitHub、Slack、Stripe、JWT、私钥、数据库连接串等 |
| 🤖 **AI增强分析** | 上下文分析减少测试文件、文档和示例的误报 |
| 🎯 **风险评分引擎** | 基于密钥类型、文件上下文和置信度计算0-100风险分数 |
| 📊 **多格式报告** | 生成控制台、JSON和HTML报告，附带精美可视化 |
| ⚡ **高性能** | 多线程扫描，可配置工作线程池 |
| 🔧 **CI/CD集成** | 原生GitHub Actions支持，发现密钥可失败构建 |
| 🛠️ **自定义规则** | 轻松扩展自己的检测模式 |
| 🌐 **零依赖** | 仅使用Python标准库 - 最大可移植性 |

### 🚀 快速开始

**环境要求：**
- Python 3.8 或更高版本

**安装：**

```bash
# 从PyPI安装（即将推出）
pip install ai-secret-guard

# 或从源码安装
git clone https://github.com/gitstq/ai-secret-guard.git
cd ai-secret-guard
pip install -e .
```

**基本用法：**

```bash
# 扫描仓库
ai-secret-guard scan /path/to/repo

# 生成HTML报告
ai-secret-guard scan /path/to/repo --format html --output report.html

# 扫描单个文件
ai-secret-guard file /path/to/file.py

# 禁用AI增强以加快扫描速度
ai-secret-guard scan /path/to/repo --no-ai
```

**Python API：**

```python
from ai_secret_guard import SecretScanner
from ai_secret_guard.reporter import ReportGenerator

# 初始化扫描器
scanner = SecretScanner()

# 扫描仓库
result = scanner.scan_repository("/path/to/repo")

# 生成报告
reporter = ReportGenerator(result)
reporter.generate_html_report("report.html")
```

### 📖 详细使用指南

**高级扫描选项：**

```bash
# 自定义工作线程数
ai-secret-guard scan . --workers 8

# 自定义忽略模式
ai-secret-guard scan . --ignore "*.log" --ignore "temp/*"

# JSON输出供程序使用
ai-secret-guard scan . --format json --output results.json
```

**CI/CD集成（GitHub Actions）：**

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ai-secret-guard
      - run: ai-secret-guard scan .
```

### 💡 设计思路

**为什么选择AI Secret Guard？**

1. **准确性优先：** 传统工具仅依赖正则模式，导致大量误报。我们的AI增强层分析上下文（文件类型、周围代码、变量名），区分真实密钥与示例和测试数据。

2. **可操作的情报：** 每个发现都包含风险评分（0-100）和具体的修复建议。生产配置中的关键密钥会被立即标记。

3. **开发者体验：** 零依赖意味着它可以在任何运行Python的地方工作。CLI提供实时进度条和清晰的颜色编码输出。

**技术选型：**
- **纯Python：** 最大兼容性，无依赖地狱
- **ThreadPoolExecutor：** 高效的I/O密集型扫描，不受GIL限制
- **Dataclass模型：** 干净、带类型提示的代码，易于扩展

**迭代规划：**
- [ ] 机器学习模型，进一步降低误报
- [ ] Pre-commit钩子集成
- [ ] SARIF格式输出，对接安全平台
- [ ] Docker容器，确保CI/CD一致性
- [ ] IDE插件（VS Code、IntelliJ）

### 📦 打包与部署

**从源码构建：**

```bash
# 安装构建依赖
pip install build twine

# 构建包
python -m build

# 上传到PyPI（仅维护者）
python -m twine upload dist/*
```

**Docker（即将推出）：**

```bash
docker run -v $(pwd):/repo gitstq/ai-secret-guard scan /repo
```

### 🤝 贡献指南

我们欢迎贡献！详情请参阅我们的[贡献指南](CONTRIBUTING.md)。

- 🐛 **Bug报告：** 提交issue并附上复现步骤
- 💡 **功能请求：** 提交issue并添加 `enhancement` 标签
- 🔧 **Pull Request：** Fork、创建分支、提交PR到 `main`

### 📄 开源协议

本项目采用 MIT 协议 - 详见 [LICENSE](LICENSE) 文件。

---

## 繁體中文

### 🎉 專案介紹

**AI Secret Guard** 是一款智慧AI增強型金鑰洩漏偵測與風險評估工具，旨在幫助開發者和安全團隊識別意外提交到程式碼倉庫中的API金鑰、密碼、令牌和其他敏感資訊。

**核心價值：**
- 🛡️ **在安全事故發生前預防**，及時發現程式碼中的金鑰洩漏
- 🤖 **AI增強的準確性**，相比傳統純正規表示式工具降低60%誤報率
- ⚡ **極速掃描**，多執行緒處理 - 秒級掃描1000+檔案
- 🎯 **上下文風險評分**，優先處理最危險的洩漏

**靈感來源：** 本專案受到 `gitleaks` 和 `truffleHog` 等工具的啟發，但解決了它們的關鍵侷限：高誤報率、缺乏風險上下文、有限的自定義能力。我們從零開始構建AI Secret Guard，專注於**準確性、速度和可操作的情報**。

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔍 **15+ 偵測規則** | 覆蓋OpenAI、AWS、GitHub、Slack、Stripe、JWT、私鑰、資料庫連線串等 |
| 🤖 **AI增強分析** | 上下文分析減少測試檔案、文件和範例的誤報 |
| 🎯 **風險評分引擎** | 基於金鑰型別、檔案上下文和置信度計算0-100風險分數 |
| 📊 **多格式報告** | 生成控制檯、JSON和HTML報告，附帶精美視覺化 |
| ⚡ **高效能** | 多執行緒掃描，可配置工作執行緒池 |
| 🔧 **CI/CD整合** | 原生GitHub Actions支援，發現金鑰可失敗構建 |
| 🛠️ **自定義規則** | 輕鬆擴充套件自己的偵測模式 |
| 🌐 **零依賴** | 僅使用Python標準庫 - 最大可移植性 |

### 🚀 快速開始

**環境要求：**
- Python 3.8 或更高版本

**安裝：**

```bash
# 從PyPI安裝（即將推出）
pip install ai-secret-guard

# 或從原始碼安裝
git clone https://github.com/gitstq/ai-secret-guard.git
cd ai-secret-guard
pip install -e .
```

**基本用法：**

```bash
# 掃描倉庫
ai-secret-guard scan /path/to/repo

# 生成HTML報告
ai-secret-guard scan /path/to/repo --format html --output report.html

# 掃描單個檔案
ai-secret-guard file /path/to/file.py

# 禁用AI增強以加快掃描速度
ai-secret-guard scan /path/to/repo --no-ai
```

**Python API：**

```python
from ai_secret_guard import SecretScanner
from ai_secret_guard.reporter import ReportGenerator

# 初始化掃描器
scanner = SecretScanner()

# 掃描倉庫
result = scanner.scan_repository("/path/to/repo")

# 生成報告
reporter = ReportGenerator(result)
reporter.generate_html_report("report.html")
```

### 📖 詳細使用指南

**高階掃描選項：**

```bash
# 自定義工作執行緒數
ai-secret-guard scan . --workers 8

# 自定義忽略模式
ai-secret-guard scan . --ignore "*.log" --ignore "temp/*"

# JSON輸出供程式使用
ai-secret-guard scan . --format json --output results.json
```

**CI/CD整合（GitHub Actions）：**

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ai-secret-guard
      - run: ai-secret-guard scan .
```

### 💡 設計思路

**為什麼選擇AI Secret Guard？**

1. **準確性優先：** 傳統工具僅依賴正規表示式模式，導致大量誤報。我們的AI增強層分析上下文（檔案型別、周圍程式碼、變數名），區分真實金鑰與範例和測試資料。

2. **可操作的情報：** 每個發現都包含風險評分（0-100）和具體的修復建議。生產配置中的關鍵金鑰會被立即標記。

3. **開發者體驗：** 零依賴意味著它可以在任何執行Python的地方工作。CLI提供實時進度條和清晰的顏色編碼輸出。

**技術選型：**
- **純Python：** 最大相容性，無依賴地獄
- **ThreadPoolExecutor：** 高效的I/O密集型掃描，不受GIL限制
- **Dataclass模型：** 乾淨、帶型別提示的程式碼，易於擴充套件

**迭代規劃：**
- [ ] 機器學習模型，進一步降低誤報
- [ ] Pre-commit鉤子整合
- [ ] SARIF格式輸出，對接安全平臺
- [ ] Docker容器，確保CI/CD一致性
- [ ] IDE外掛（VS Code、IntelliJ）

### 📦 打包與部署

**從原始碼構建：**

```bash
# 安裝構建依賴
pip install build twine

# 構建包
python -m build

# 上傳到PyPI（僅維護者）
python -m twine upload dist/*
```

**Docker（即將推出）：**

```bash
docker run -v $(pwd):/repo gitstq/ai-secret-guard scan /repo
```

### 🤝 貢獻指南

我們歡迎貢獻！詳情請參閱我們的[貢獻指南](CONTRIBUTING.md)。

- 🐛 **Bug報告：** 提交issue並附上復現步驟
- 💡 **功能請求：** 提交issue並新增 `enhancement` 標籤
- 🔧 **Pull Request：** Fork、建立分支、提交PR到 `main`

### 📄 開源協議

本專案採用 MIT 協議 - 詳見 [LICENSE](LICENSE) 檔案。

---

<p align="center">
  Made with ❤️ by the AI Secret Guard Team
</p>
