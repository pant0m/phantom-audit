# AI Security Audit Skills

AI Agent 驱动的代码安全审计技能包。适用于 **Claude Code** 和 **Hermes Agent** 两大平台。

> 由攻防安全团队实战打磨，覆盖 OWASP Top 10、CWE Top 25、多语言深度分析、LLM 红队测试。

## 技能清单

### Claude Code Skills（`~/.claude/skills/` 安装）

| 技能 | 用途 | 特色 |
|------|------|------|
| **code-security-audit** | 企业级代码安全审计 | 7 阶段流水线、22+ 漏洞类别、多 Agent 并行扫描、自演化知识库、反幻觉验证、JAR/WAR 反编译支持 |
| **ctf-rce-hunting** | CTF/授权渗透 RCE 猎杀 | 反编译驱动的 sink 发现、多角度攻击向量、完整攻击链构造 |

### Hermes Agent Skills（`skills/` 目录安装）

| 技能 | 用途 | 特色 |
|------|------|------|
| **red-teaming/godmode** | LLM 越狱 & 红队测试 | GODMODE 系统提示模板、Parseltongue 33 种混淆技术、ULTRAPLINIAN 多模型竞速、自动越狱流水线 |
| **github/github-code-review** | GitHub PR 代码审查 | 本地变更审查、PR inline 评论、结构化审查清单（正确性/安全/质量/测试/性能/文档） |
| **github/codebase-inspection** | 代码仓库度量分析 | LOC 统计、语言分布、代码/注释比、pygount 集成 |
| **software-development/requesting-code-review** | 提交前自动验证 | 静态安全扫描、基线感知质量门禁、独立审查子 Agent、自动修复循环 |

## 快速安装

### 方式一：一键安装（推荐）

```bash
git clone https://github.com/pant0m/pant0m.git ai-security-skills
cd ai-security-skills
./install.sh
```

### 方式二：手动安装

**Claude Code Skills：**

```bash
# 安装 code-security-audit
cp -r claude-code-skills/code-security-audit ~/.claude/skills/

# 安装 ctf-rce-hunting
cp -r claude-code-skills/ctf-rce-hunting ~/.claude/skills/
```

**Hermes Agent Skills：**

```bash
HERMES_SKILLS="${HERMES_HOME:-$HOME/.hermes}/skills"

# 安装 godmode 红队技能
cp -r hermes-skills/red-teaming "$HERMES_SKILLS/"

# 安装代码审查技能
cp -r hermes-skills/github "$HERMES_SKILLS/"
cp -r hermes-skills/software-development "$HERMES_SKILLS/"
```

## 技能详解

### code-security-audit — 企业代码审计

7 阶段全流程审计流水线：

```
Phase 0: 知识加载（从历史审计自动学习）
Phase 1: 侦察 & 攻击面映射（端点、数据流、信任边界）
Phase 1.5: JAR/WAR 反编译（自动 CFR 反编译 + 内部类覆盖）
Phase 2: 确定性工具预扫（Semgrep + Gitleaks + OSV-Scanner）
Phase 3: 多 Agent 深度分析（22+ 漏洞类别并行扫描）
Phase 4: 语言特定深度分析（Go/Python/Java/TS/C/PHP/Ruby/Rust/.NET/Kotlin）
Phase 5: 报告生成（严重性分级 + 修复建议 + PoC）
Phase 6: 反馈收集（确认/误报 → 知识库自演化）
```

支持语言：Go, Python, Java, TypeScript/JavaScript, C/C++, PHP, Ruby, Rust, C#/.NET, Kotlin/Swift

覆盖漏洞类别：
- 注入（SQLi, CMDi, XSS, LDAP, NoSQL, SSTI, XXE, CRLF, Email Header）
- 认证 & 授权（JWT, OAuth/OIDC, SSO, 密码重置, 验证码, 路由绕过）
- 敏感数据（硬编码凭证, 日志泄露, 信息暴露）
- 加密（弱算法, ECB, 硬编码密钥, 随机数）
- SSRF, 路径穿越, 反序列化, 内存安全, 竞态条件
- 文件上传（12 种攻击维度, 跨 8 种语言）
- 提权链路库（20 种实战验证路径）
- 现代协议（WebSocket, GraphQL, gRPC, MQ, 缓存, HTTP 走私）
- 业务逻辑, ReDoS, 原型链污染, 点击劫持
- 供应链攻击（依赖混淆, 恶意脚本, CVE 检测）

**自演化知识库**：每次审计后，确认的漏洞模式自动写入 `references/confirmed-patterns.md`，后续审计自动优先扫描。

### godmode — LLM 红队测试

三种攻击模式：
1. **GODMODE CLASSIC** — 针对不同模型的系统提示模板（Claude/GPT/Gemini/Grok/DeepSeek）
2. **PARSELTONGUE** — 33 种输入混淆技术（Leetspeak/Unicode/Braille/Morse 等）
3. **ULTRAPLINIAN** — 多模型竞速评分（55 模型 × 5 档）

自动越狱：
```python
exec(open("skills/red-teaming/godmode/scripts/load_godmode.py").read())
result = auto_jailbreak()  # 自动检测模型 → 选策略 → 测试 → 锁定
```

### requesting-code-review — 提交前验证

独立审查 + 自动修复循环：
```
Step 1: git diff 获取变更
Step 2: 静态安全扫描（硬编码密钥、shell 注入、eval、反序列化、SQL 注入）
Step 3: 基线测试 & lint（增量 = 只报新问题）
Step 4: 独立审查子 Agent（全新上下文，不受实现者偏见影响）
Step 5: 评估 → 通过 or 自动修复（最多 2 轮）
Step 6: 标记 [verified] 提交
```

## 依赖工具（可选，增强扫描精度）

| 工具 | 用途 | 安装 |
|------|------|------|
| Semgrep | 语法感知模式匹配 | `pip install semgrep` |
| Gitleaks | 硬编码密钥检测 | `brew install gitleaks` |
| OSV-Scanner | 依赖 CVE 检测 | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| Bandit | Python 安全扫描 | `pip install bandit` |
| pygount | 代码行数统计 | `pip install pygount` |
| CFR | Java 反编译器 | `curl -L -o /tmp/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar` |

## 项目结构

```
.
├── README.md
├── install.sh                          # 一键安装脚本
├── claude-code-skills/                 # Claude Code 技能
│   ├── code-security-audit/            # 企业代码安全审计
│   │   ├── SKILL.md                    # 主技能文件（7 阶段流水线）
│   │   ├── references/
│   │   │   ├── confirmed-patterns.md   # 已确认漏洞模式库
│   │   │   ├── false-positives.md      # 误报排除规则
│   │   │   └── framework-fingerprints.md # 框架安全指纹
│   │   └── scripts/
│   │       ├── pre-scan.md             # Phase 2 预扫描命令集
│   │       ├── jar-decompile.md        # JAR/WAR 反编译流水线
│   │       ├── coverage-check.md       # Phase 3.5 覆盖率验证
│   │       └── post-audit-feedback.md  # Phase 6 反馈收集
│   └── ctf-rce-hunting/               # CTF/渗透 RCE 猎杀
│       └── SKILL.md
├── hermes-skills/                      # Hermes Agent 技能
│   ├── red-teaming/
│   │   └── godmode/                    # LLM 越狱 & 红队
│   │       ├── SKILL.md
│   │       ├── references/
│   │       ├── scripts/
│   │       └── templates/
│   ├── github/
│   │   ├── github-code-review/         # GitHub PR 审查
│   │   └── codebase-inspection/        # 代码仓库度量
│   └── software-development/
│       └── requesting-code-review/     # 提交前验证
└── LICENSE
```

## License

MIT

## Author

[@pant0m](https://github.com/pant0m) — 攻防安全团队
