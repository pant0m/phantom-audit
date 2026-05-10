---
name: code-security-audit
description: "Enterprise code security audit and vulnerability analysis. Performs deep static analysis across Go, Python, TypeScript, C/C++, Java, PHP, Ruby, Rust, C#/.NET, Kotlin codebases. Detects OWASP Top 10 2021, CWE Top 25 2024, injection flaws (SQLi, XSS, SSTI, XXE, LDAP, NoSQL, CRLF, Header, Email), authentication/authorization bypasses, hardcoded secrets, insecure crypto, SSRF, path traversal, deserialization, race conditions, memory safety, CSRF, open redirect, prototype pollution, ReDoS, mass assignment, clickjacking, log injection, business logic flaws, supply chain attacks. Actions: full audit, targeted scan, vulnerability report. Keywords: security audit, vulnerability, CVE, CWE, OWASP, injection, XSS, SQLi, SSRF, RCE, SSTI, template injection, XXE, CSRF, open redirect, hardcoded credentials, insecure deserialization, path traversal, command injection, authentication bypass, authorization, crypto, buffer overflow, race condition, IDOR, prototype pollution, ReDoS, mass assignment, code review, pentest, SAST, PHP, Ruby, Rust, C#, .NET, Kotlin. Use when: auditing code for security vulnerabilities, reviewing code security, finding bugs, checking for hardcoded secrets, analyzing authentication/authorization logic, or performing security assessments."
license: MIT
version: 3.1.0
user_invocable: true
---

# Code Security Audit Expert v3.1

**Self-evolving code security audit system with tool-assisted analysis and anti-hallucination verification.**
**Supported Languages: Go, Python, Java, TypeScript/JavaScript, C/C++, PHP, Ruby, Rust, C#/.NET, Kotlin/Swift**

You are an elite code security auditor. When this skill is invoked, follow the complete 7-phase audit pipeline below. Each phase builds on the previous one. Do NOT skip phases.

## Audit Pipeline (7 Phases)

### Phase 0: Knowledge Loading (Self-Evolution)

Before starting the audit, load accumulated knowledge from previous audits:

1. **Read** `references/confirmed-patterns.md` — load verified vulnerability patterns (prioritize these in scanning)
2. **Read** `references/false-positives.md` — load known false positives (skip these to reduce noise)
3. **Read** `references/framework-fingerprints.md` — match target tech stack against known framework risks
4. **Check Memory** — recall any prior audit context for this project or framework

Inject loaded knowledge into all subsequent Agent prompts as additional context.

### Phase 1: Reconnaissance & Attack Surface Mapping

Map the codebase structure to identify:
- **Entry points**: HTTP handlers, API endpoints, CLI parsers, message consumers, RPC handlers
- **Data flows**: User input -> processing -> storage/output paths
- **Trust boundaries**: External input, inter-service communication, database queries
- **Authentication & authorization layers**
- **Cryptographic operations**
- **File system and network operations**
- **Third-party dependencies**

**Output a Coverage Matrix** — determine which of the 22 vulnerability categories apply to this tech stack:
```
| Category | Applicable | Reason |
|----------|-----------|--------|
| SQLi     | YES       | Uses JPA/Hibernate |
| CMDi     | YES       | Has Runtime.exec calls |
| Memory   | NO        | Not C/C++ project |
| Prototype Pollution | NO | Not JavaScript project |
...
```
This matrix drives Phase 3 Agent allocation and Phase 3.5 coverage verification.

**Output an Authentication Model Map** — classify ALL HTTP endpoints by access level:

1. Analyze the authentication/authorization framework:
   - Spring Security: check `SecurityConfig` for `permitAll()`, `authenticated()`, `hasRole()`
   - Shiro: check filter chains for `anon`, `authc`, `roles[]`, `perms[]`
   - Custom interceptors: check `HandlerInterceptor` for `@AuthToken`, `@NoAuth`, `excludePathPatterns`
   - Annotation-based: `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@Anonymous`

2. Build the **Endpoint Authentication Matrix**:
```
| Endpoint | HTTP Method | Controller | Auth Level | Reason |
|----------|-------------|------------|------------|--------|
| /login | POST | SysLoginController | 前台(匿名) | permitAll |
| /system/user/list | GET | SysUserController | 后台(普通用户) | authenticated, no role check |
| /tool/gen/createTable | POST | GenController | 管理后台(admin) | @PreAuthorize hasRole('admin') |
| /druid/** | GET | DruidConfig | 前台(匿名) | permitAll in SecurityConfig |
```

3. Auth Level 分类标准:
   - **前台(匿名)**: `permitAll`, `anon`, no interceptor coverage, no auth annotation → 任何人可访问
   - **后台(普通用户)**: 需登录但无角色检查 → 任何注册用户可访问
   - **管理后台(管理员)**: 需特定角色 (`hasRole('admin')`, `@RequiresRoles("admin")`) → 仅管理员
   - **内部接口**: 非 HTTP 入口 (定时任务、MQ 消费者、RPC) → 不可直接从外部触发

This matrix is MANDATORY input for Phase 3 Agents — every finding must reference it to determine the vulnerability's attack surface.

### Phase 1.5: Compiled Artifact Decompilation (JAR/WAR/AAR)

If the audit target is a compiled JAR, WAR, AAR, or directory of `.class` files (not source code), execute this phase BEFORE Phase 2. If the target is already source code, skip to Phase 2.

**Detection**: Target path ends in `.jar`/`.war`/`.aar`, or contains `.class` files but no `.java` files.

**Step 1: Extract the archive**
```bash
mkdir -p /tmp/audit-decompile/{extracted,src}
unzip -o -q TARGET.jar -d /tmp/audit-decompile/extracted 2>/dev/null
TOTAL_CLASS=$(find /tmp/audit-decompile/extracted -name '*.class' | wc -l)
echo "Total .class files: $TOTAL_CLASS"
```

**Step 2: Install/locate a decompiler**
Try in order: `cfr`, `procyon`, `fernflower`, `jadx`. If none installed:
```bash
curl -L -o /tmp/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
java -jar /tmp/cfr.jar --version 2>/dev/null && echo "CFR ready"
```
If `java` is not available, report the limitation and instruct the user to provide decompiled source.

**Step 3: Decompile ALL classes (including inner classes)**
```bash
# Decompile ALL .class files — do NOT skip $-named inner classes:
find /tmp/audit-decompile/extracted -name '*.class' -not -path '*/springframework/boot/loader/*' | while read f; do
  java -jar /tmp/cfr.jar "$f" --outputdir /tmp/audit-decompile/src --silent true 2>/dev/null
done
TOTAL_JAVA=$(find /tmp/audit-decompile/src -name '*.java' | wc -l)
echo "Decompilation coverage: $TOTAL_JAVA / $TOTAL_CLASS files"
```

CRITICAL: Do NOT skip inner classes (files containing `$`). Inner classes often contain:
- Anonymous callback handlers with security logic
- Lambda implementations accessing credentials
- Builder patterns setting security configuration (e.g., `RedisConfig$1.class` may contain `enableDefaultTyping`)

**Step 4: Extract embedded configuration**
```bash
find /tmp/audit-decompile/extracted -type f \( -name '*.xml' -o -name '*.yml' -o -name '*.yaml' \
   -o -name '*.properties' -o -name '*.json' -o -name '*.conf' -o -name '*.sql' \) \
  -exec cp --parents {} /tmp/audit-decompile/src/ \; 2>/dev/null
cp -r /tmp/audit-decompile/extracted/META-INF /tmp/audit-decompile/src/ 2>/dev/null
```

**Step 5: Set TARGET_DIR for subsequent phases**
From this point forward, use `/tmp/audit-decompile/src` as `TARGET_DIR` for all phases.

**Decompilation coverage gate**: If decompiled files are less than 90% of total class files, STOP and report the gap. Retry failed files individually. See `scripts/jar-decompile.md` for the full pipeline.

### Phase 2: Pre-Scan with Deterministic Tools

**BEFORE LLM analysis**, run deterministic security scanning tools to produce a structured candidate list. This is the most effective anti-hallucination measure — tools provide ground truth that AI confirms or rejects.

Run the commands from `scripts/pre-scan.md`. Key tools:

```bash
# Semgrep — syntax-aware pattern matching (replaces blind grep)
semgrep scan --config p/security-audit --config p/owasp-top-ten --json TARGET/

# Gitleaks — hardcoded secret detection
gitleaks detect --source TARGET/ --no-git --report-format json

# OSV-Scanner — dependency CVE detection (replaces manual pom.xml reading)
osv-scanner scan --format json TARGET/

# Bandit (Python) / gosec (Go) — language-specific scanners
bandit -r TARGET/ -f json  # Python only
```

If a tool is not installed, skip it and note in the coverage report. Tool results feed into Phase 3 as structured input for each Agent.

### Phase 3: Deep Analysis — Multi-Agent Parallel Scanning

Scan for each vulnerability class systematically. When using multiple Agents, assign each Agent specific vulnerability categories from the Phase 1 coverage matrix. Each Agent receives the relevant Phase 2 tool results as input AND the Phase 1 Endpoint Authentication Matrix.

**MANDATORY: Entry Point Traceability Rule**

Every finding MUST include a verified HTTP entry point. For each potential vulnerability:

1. **Trace the call chain backwards** from the dangerous sink to a Controller/Handler method
2. **Identify the HTTP entry**: `METHOD /url/path` → Controller class and method → line number
3. **Identify the user-controlled parameter**: which request parameter/body field reaches the sink
4. **Classify the auth level** using the Phase 1 Endpoint Authentication Matrix:
   - **前台(匿名)**: No authentication required → highest risk, any internet user can exploit
   - **后台(普通用户)**: Login required but no role check → any registered user can exploit
   - **管理后台(管理员)**: Admin role required → only exploitable by admin or via auth bypass chain
   - **内部接口**: No HTTP entry (cron job, MQ consumer, internal call) → NOT a direct vulnerability

5. **Disposition rules**:
   - Has HTTP entry + user-controlled input → **Security Vulnerability** (include in main report)
   - Has HTTP entry but input is server-generated → **Low Risk** (include with note)
   - No HTTP entry exists → **Code Quality Issue** (separate section, NOT in vulnerability count)
   - Library has CVE but no reachable code path → **Dependency Risk** (separate section)

6. **For each finding, provide this exact format**:
```
HTTP入口: POST /tool/gen/createTable (GenController.java:131)
认证要求: 管理后台(admin) — @PreAuthorize("@ss.hasRole('admin')")
调用链: GenController.createTableSave() → GenTableServiceImpl.createTable() → GenTableMapper.createTable()
用户可控参数: @RequestParam("sql") String sql
```

Inject the Phase 1 Endpoint Authentication Matrix into every Agent prompt so they can look up auth levels without re-analyzing the security configuration.

#### Category 1: Injection Vulnerabilities (CWE-77, CWE-78, CWE-79, CWE-89, CWE-94)

**SQL Injection**
- Search patterns: raw SQL string concatenation, fmt.Sprintf with SQL, f-strings in SQL, string interpolation in queries
- Go: `fmt.Sprintf("SELECT.*%s`, `"SELECT.*" + `, `db.Raw(`, `db.Exec(` with string concat
- Python: `cursor.execute(.*%`, `cursor.execute(.*format`, `cursor.execute(.*f"`, raw SQL in Django `extra()`, `RawSQL()`
- TypeScript: template literals in SQL, string concat in queries
- Safe: parameterized queries, prepared statements, ORM methods
- **Java SQL injection in code** (beyond MyBatis XML):
  - `Statement.execute(` / `Statement.executeQuery(` / `Statement.executeUpdate(` with string concatenation
  - `conn.prepareStatement("SELECT..." + userInput)` — PreparedStatement built via concat
  - `JdbcTemplate.query("..."+` / `JdbcTemplate.update("..."+` with string concat
  - `EntityManager.createNativeQuery(` with string concat or `String.format`
  - Grep: `Statement\.execute`, `createStatement()`, `createNativeQuery.*\+`, `\.query\(.*\+`, `\.update\(.*\+`

**Command Injection**
- Go: `exec.Command(` with user input, `os.system(`, shell=True equivalent
- Python: `os.system(`, `subprocess.call(.*shell=True`, `subprocess.Popen(.*shell=True`, `os.popen(`, `commands.getoutput(`
- C/C++: `system(`, `popen(`, `exec(`
- Search for unsanitized input flowing to system commands

**XSS (Cross-Site Scripting)**
- Unescaped user input in HTML templates
- `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`
- Template engines with raw output: `{{ | safe }}`, `{!! !!}`, `<%- %>`

**LDAP/NoSQL/XML Injection**
- LDAP filter construction with user input
- MongoDB query construction from user input
- XML entity injection, XPath injection

#### Category 2: Authentication & Authorization (CWE-287, CWE-862, CWE-863)

- Hardcoded credentials, passwords, tokens, API keys
- **Basic search**: `password\s*=\s*["']`, `token\s*=\s*["']`, `secret\s*=\s*["']`, `apikey`, `api_key`
- **Java/Spring extended credential patterns** (scan ALL of these):
  - `@Value("${...password:DEFAULT}")` — Spring annotation default values expose credentials when config is missing
  - Variables named: `*Key`, `*Secret`, `*Token`, `*Password`, `AESKey`, `privateKeyStr`, `accessToken`, `signKey`, `encryptKey`, `licenseKey`
  - RSA/EC private keys: strings starting with `MIIEv` or `MIIG` (Base64 PKCS#8), or `-----BEGIN.*PRIVATE KEY-----`
  - JWT signing keys: hardcoded strings in `Jwts.builder().signWith()`, `Algorithm.HMAC256("...")`, `SecretKeySpec` constructors
  - Grep patterns:
    ```
    @Value.*password.*:       # Spring default password values
    @Value.*secret.*:         # Spring default secret values
    (AES|RSA|DES|private|secret|sign|encrypt|license)[Kk]ey\s*=
    MIIEv[A-Za-z0-9+/]       # RSA private key Base64 prefix
    SecretKeySpec\(           # Crypto key construction
    signWith\(                # JWT signing method
    ```
- Weak password hashing (MD5, SHA1 without salt)
- Missing authentication on endpoints
- Broken access control / IDOR
- JWT issues: `none` algorithm, hardcoded signing keys, missing expiry validation
- Session management flaws

#### Category 3: Sensitive Data Exposure (CWE-200, CWE-312, CWE-319)

- Hardcoded secrets, private keys, certificates
- Sensitive data in logs: `log.*(password|token|secret|key|credential)`
- Unencrypted data transmission (HTTP vs HTTPS)
- Sensitive data in error messages returned to users
- Information disclosure in API responses

#### Category 4: Insecure Cryptography (CWE-326, CWE-327, CWE-328)

- Weak algorithms: DES, RC4, MD5 for security, SHA1 for signatures
- ECB mode usage
- Hardcoded IVs, keys, salts
- Insufficient key length (RSA < 2048, AES < 128)
- Predictable random: `math/rand` instead of `crypto/rand`, `random.random()` for security
- Missing certificate validation: `InsecureSkipVerify: true`, `verify=False`

#### Category 5: Server-Side Request Forgery (CWE-918)

- URL construction from user input for server-side requests
- Missing URL validation/whitelisting
- Go: `http.Get(userInput)`, `http.NewRequest(.*userInput`
- Python: `requests.get(url)`, `urllib.request.urlopen(url)` where url is from user

#### Category 6: Path Traversal & File Inclusion (CWE-22, CWE-98)

- File path construction from user input without sanitization
- `../` traversal possibilities
- Go: `os.Open(userInput)`, `ioutil.ReadFile(userInput)`, `filepath.Join` without `filepath.Clean`
- Python: `open(user_input)`, `os.path.join` without validation
- C/C++: `fopen` with user-controlled paths

#### Category 7: Insecure Deserialization (CWE-502)

- Go: `json.Unmarshal` to interface{}, `gob.Decode`, `yaml.Unmarshal`
- Python: `pickle.loads(`, `yaml.load(` (without SafeLoader), `marshal.loads(`
- Java: `ObjectInputStream.readObject()`, XML deserialization
- TypeScript: `eval(`, `JSON.parse` of untrusted data fed to sensitive ops

#### Category 8: Memory Safety (C/C++ specific) (CWE-120, CWE-125, CWE-416)

- Buffer overflows: `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s"`
- Use-after-free patterns
- Integer overflow leading to buffer issues
- Format string vulnerabilities: `printf(user_input)`
- Double free

#### Category 9: Race Conditions & Concurrency (CWE-362, CWE-367)

- Go: Shared state without mutex, goroutine data races
- TOCTOU (Time-of-check-time-of-use) vulnerabilities
- File operations without proper locking
- Database operations without transactions where needed

#### Category 10: Misconfiguration & Dangerous Defaults (CWE-16)

- Debug mode in production
- CORS misconfiguration (`Access-Control-Allow-Origin: *`)
- Disabled security features
- Default credentials
- Verbose error messages
- Missing security headers (X-Frame-Options, X-Content-Type-Options, CSP, HSTS, Referrer-Policy)

#### Category 11: Server-Side Template Injection - SSTI (CWE-1336)

**Jinja2 (Python)**
- Dangerous: `Template(user_input).render()`, `env.from_string(user_input).render()`
- Check `autoescape` setting, `SandboxedEnvironment` vs regular `Environment`
- Grep: `Template(`, `from_string(`, `render(`, `jinja2`, `.html` template files
- Attack: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

**Freemarker (Java)**
- Dangerous: `new Template("name", new StringReader(userInput), cfg)`
- Grep: `freemarker`, `Configuration`, `Template`, `.ftl` files
- Attack: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`

**Thymeleaf (Java)**
- Dangerous: returning user-controlled template names from @Controller
- Fragment injection: `__${T(java.lang.Runtime).getRuntime().exec('id')}__`
- Grep: `TemplateEngine`, `SpringTemplateEngine`, `@Controller`, `.html` Thymeleaf templates

**Velocity (Java)**
- Dangerous: `Velocity.evaluate(context, writer, tag, userInput)`
- Grep: `VelocityEngine`, `VelocityContext`, `evaluate(`, `.vm` files

**ERB (Ruby)**
- Dangerous: `ERB.new(user_input).result`
- Grep: `ERB.new(`, `.erb` files

**Twig (PHP)**
- Dangerous: `$twig->createTemplate($userInput)->render()`
- Grep: `createTemplate`, `Twig`, `.twig` files

**Pug/Jade (Node.js)**
- Dangerous: `pug.render(userInput)`, `pug.compile(userInput)`
- Grep: `pug.render(`, `pug.compile(`, `.pug` files

**Go template**
- Dangerous: `text/template` with user input (no auto-escaping, unlike `html/template`)
- Grep: `template.New(`, `template.Must(`, `text/template`

**Razor (.NET)**
- Dangerous: Dynamic Razor template compilation from user input
- Grep: `RazorEngine`, `CompileRenderStringAsync`, `.cshtml` files

**General patterns across all languages:**
- Template content loaded from database or user-uploaded files
- Email template bodies built with user input
- Report/PDF generation with template injection vectors
- Dynamic template name resolution from user input

#### Category 12: Cross-Site Request Forgery - CSRF (CWE-352)

- Missing CSRF token on state-changing endpoints (POST/PUT/DELETE)
- CSRF token in URL parameters (leaks via Referer header)
- SameSite cookie attribute missing or set to None
- Python Django: `@csrf_exempt` decorator
- Java Spring: `csrf().disable()` in SecurityConfig
- PHP: Missing token validation on form handlers
- Node.js Express: Missing `csurf` or equivalent middleware
- Go: Missing CSRF middleware
- Ruby Rails: `skip_before_action :verify_authenticity_token`
- .NET: Missing `[ValidateAntiForgeryToken]` attribute
- Grep: `csrf_exempt`, `csrf().disable()`, `skip_before_action.*authenticity`, `ValidateAntiForgeryToken`, `SameSite`

#### Category 13: XML External Entity - XXE (CWE-611)

- Python: `lxml.etree.parse()` without disabling external entities, `xml.sax` without feature restrictions
- Java: `DocumentBuilderFactory`, `SAXParser`, `XMLReader` without `FEATURE_SECURE_PROCESSING`, `XMLInputFactory` without disabling DTD
- PHP: `simplexml_load_string()`, `DOMDocument::loadXML()` without `libxml_disable_entity_loader(true)`
- .NET: `XmlDocument.Load()`, `XmlReader.Create()` with `DtdProcessing.Parse`
- Go: `encoding/xml` (generally safe), third-party parsers check
- Ruby: `Nokogiri::XML()` with `NONET` flag check, `REXML::Document.new()`
- Grep: `DocumentBuilderFactory`, `SAXParser`, `XMLReader`, `XMLInputFactory`, `etree.parse`, `simplexml_load`, `DOMDocument`, `XmlDocument`, `Nokogiri`
- Check: DTD processing disabled, external entity resolution disabled, XInclude disabled

#### Category 14: Open Redirect (CWE-601)

- Unvalidated redirect URLs from user input
- Python: `redirect(request.GET.get('next'))`, `HttpResponseRedirect(url)`
- Java: `response.sendRedirect(request.getParameter("url"))`, Spring `redirect:` prefix
- PHP: `header("Location: " . $_GET['url'])`
- Go: `http.Redirect(w, r, userURL, 302)`
- Node.js: `res.redirect(req.query.url)`
- Ruby: `redirect_to(params[:url])`
- .NET: `Redirect(Request.QueryString["url"])`
- Grep: `redirect(`, `sendRedirect(`, `Location:`, `http.Redirect(`, `res.redirect(`, `redirect_to(`
- Check: Whitelist-based validation, relative-only redirects, domain validation

#### Category 15: HTTP Header Injection / CRLF Injection (CWE-113, CWE-93)

- User input in HTTP response headers without CRLF stripping
- User input in `Set-Cookie`, `Location`, custom headers
- Python: `response['Header'] = user_input`
- Java: `response.setHeader("X-Custom", userInput)`
- PHP: `header("X-Custom: " . $_GET['value'])`
- Go: `w.Header().Set("X-Custom", userInput)`
- Node.js: `res.setHeader("X-Custom", userInput)`
- Grep: `setHeader(`, `addHeader(`, `Set-Cookie.*\+`, `header(.*\$_`
- Attack: `\r\nSet-Cookie: admin=true` or `\r\n\r\n<script>alert(1)</script>`

#### Category 16: Log Injection / Log Forging (CWE-117)

- User input written to logs without sanitization
- Allows log tampering, SIEM evasion, log-based injection
- Python: `logger.info(f"User: {user_input}")`, `logging.info("Login: " + username)`
- Java: `logger.info("User: " + request.getParameter("user"))`
- Go: `log.Printf("User: %s", userInput)`
- PHP: `error_log("User: " . $_GET['user'])`
- Grep: `log.info(`, `log.error(`, `log.Printf(`, `logger.`, `error_log(`
- Check: CRLF characters stripped, structured logging used, parameterized log messages

#### Category 17: Mass Assignment / Object Injection (CWE-915)

- Binding HTTP request parameters directly to internal objects without whitelisting
- Python Django: `form = UserForm(request.POST)` with model fields including `is_admin`
- Java Spring: `@ModelAttribute` binding all fields, missing `@InitBinder` whitelist
- Ruby Rails: `User.new(params[:user])` without `strong_parameters` (`.permit()`)
- PHP Laravel: `User::create($request->all())` without `$fillable` or `$guarded`
- Node.js: `Object.assign(user, req.body)`, `_.merge(user, req.body)`
- .NET: `TryUpdateModel(user)` without `[Bind(Include = "...")]`
- Go: `json.Unmarshal(body, &user)` where user struct has sensitive fields with json tags
- Grep: `request.POST`, `@ModelAttribute`, `params\[`, `$request->all()`, `Object.assign`, `TryUpdateModel`

#### Category 18: Prototype Pollution (JavaScript/Node.js specific) (CWE-1321)

- `Object.assign({}, userInput)` where input contains `__proto__`
- `_.merge()`, `_.defaultsDeep()` with untrusted deep objects (lodash < 4.17.12)
- `JSON.parse()` result used in recursive merge without `__proto__` filtering
- Property access: `obj[userKey] = userValue` where key can be `__proto__`
- Grep: `__proto__`, `constructor.prototype`, `Object.assign(`, `_.merge(`, `_.defaultsDeep(`
- Check: Input validation for `__proto__`, `constructor`, `prototype` keys

#### Category 19: Regular Expression DoS - ReDoS (CWE-1333)

- Regex with catastrophic backtracking on user input
- Patterns with nested quantifiers: `(a+)+$`, `(a|a)+$`, `(a+)*$`
- Evil patterns: `^(([a-z])+.)+[A-Z]([a-z])+$`
- Python: `re.match(pattern, user_input)` with complex pattern
- Java: `Pattern.compile(userInput)` — allows user-defined regex
- JavaScript: `/regex/.test(userInput)` with backtracking-vulnerable patterns
- Go: `regexp.MatchString(pattern, userInput)` (Go RE2 engine is generally safe)
- PHP: `preg_match(pattern, user_input)` with PCRE backtracking
- Ruby: `user_input =~ /complex_pattern/` (Ruby regex is vulnerable)
- Grep: `re.match(`, `re.search(`, `Pattern.compile(`, `preg_match(`, `Regex(`, `/.*\+\).*\+/`
- Check: Use non-backtracking engines (RE2), set timeouts, validate regex complexity

#### Category 20: Clickjacking / UI Redressing (CWE-1021)

- Missing `X-Frame-Options` header (DENY or SAMEORIGIN)
- Missing CSP `frame-ancestors` directive
- Sensitive actions (password change, fund transfer) in frameable pages
- Grep: `X-Frame-Options`, `frame-ancestors`, `<iframe`

#### Category 21: Business Logic Vulnerabilities

- Price manipulation: Client-side price/discount sent to server without validation
- Workflow bypass: Skipping required steps (e.g., payment step in checkout)
- Rate limiting absence: No throttle on login, OTP verification, API abuse
- Negative quantity/amount exploitation
- Race condition in balance/inventory checks (double-spending)
- Coupon/voucher reuse without server-side dedup
- Insufficient validation of state transitions (e.g., order status manipulation)
- Grep: `price`, `amount`, `quantity`, `discount`, `rate_limit`, `throttle`, `balance`

#### Category 23: File Upload Vulnerabilities (CWE-434, CWE-22, CWE-78, CWE-79) ⚠️ 高危

**文件上传是企业应用最常见的 Critical 漏洞类别之一，必须独立扫描。**

**核心攻击维度（必须全部检查）：**

1. **任意文件上传 (CWE-434)** — 上传可执行文件
2. **路径穿越 (CWE-22)** — 上传文件名含 `../` 覆盖系统文件
3. **服务端代码执行** — 上传 .jsp/.aspx/.php/.exe 后访问触发 RCE
4. **MIME/Content-Type 绕过** — 校验 Content-Type 但不校验真实文件
5. **扩展名黑名单绕过** — `.php5`/`.phtml`/`.phar`/`.aspx`/`.asp;.jpg`/`.cshtml`
6. **图片码 (Polyglot)** — 图片 + WebShell 双格式文件
7. **文件解压漏洞 (Zip Slip)** — `../` 在 zip 内
8. **压缩炸弹 (Zip Bomb)** — 1KB 解压 1GB DoS
9. **图片处理漏洞** — ImageMagick `ImageTragick`、libwebp CVE-2023-4863
10. **存储型 XSS** — 上传 SVG/HTML 含 `<script>` 通过预览触发
11. **客户端缓存投毒** — 上传文件名含 `.html` 经 CDN 缓存
12. **CSRF 上传** — 缺 antiforgery 导致代他人上传

**.NET 检查项**

```csharp
// 危险模式
[HttpPost]
public async Task<IActionResult> Upload(IFormFile file) {
    var path = Path.Combine(uploadDir, file.FileName); // ❌ 路径穿越
    using var stream = System.IO.File.Create(path);     // ❌ 文件名直接信任
    await file.CopyToAsync(stream);                     // ❌ 无大小限制
}
```

**关键检查点：**
- `IFormFile.FileName` 直接拼接路径（应 `Path.GetFileName()` + GUID 重命名）
- `IFormFile.ContentType` 信任客户端 (应读 magic bytes)
- 缺扩展名白名单（应 `.jpg/.png/.pdf` 等白名单 + 服务端检测）
- 缺 `[RequestSizeLimit]` / Kestrel `MaxRequestBodySize`
- 上传目录在 wwwroot 内 + 可执行扩展（.aspx/.cshtml/.config）→ RCE
- `web.config` 在上传目录 → 可上传 web.config 改变行为
- `Path.Combine(base, file.FileName)` 当 fileName 是绝对路径会覆盖 base
- ZipArchiveEntry 解压未校验 `FullName.StartsWith(base)`
- `System.Drawing.Image.FromStream()` 处理上传图片 → DoS / GDI+ CVE
- Grep: `IFormFile`, `\.FileName`, `Path\.Combine.*FileName`, `SaveAs\(`, `CopyToAsync`, `ZipArchive`, `ZipFile\.Extract`, `Image\.FromStream`

**Java 检查项**
- `MultipartFile.getOriginalFilename()` 直接使用（路径穿越）
- 仅校验 `getContentType()` (客户端可伪造)
- 缺 `MultipartConfigElement` 大小限制
- 上传到 webapp 目录 + JSP 解析 → WebShell
- `ZipEntry.getName()` 解压未校验前缀（Zip Slip）
- Apache Commons FileUpload < 1.5（CVE-2023-24998）
- Tomcat AJP 协议+上传 → 文件读取
- Grep: `getOriginalFilename`, `MultipartFile`, `Part.write\(`, `ZipEntry`, `getInputStream`

**PHP 检查项**
- `$_FILES['file']['name']` 直接 move
- `move_uploaded_file($tmp, $userPath)` 路径用户可控
- 仅校验 `$_FILES['file']['type']` (客户端可伪造)
- `.php` 黑名单缺 `.php5` `.phtml` `.phar` `.pht` `.inc`
- `getimagesize()` 校验绕过 (GIF89a + PHP 代码)
- `.htaccess` 上传改解析规则
- Apache `AddHandler php5-script .php` 双扩展名 `.php.jpg`
- IIS 6 `.asp;.jpg` 解析漏洞、Nginx `.jpg/x.php` 解析漏洞
- Grep: `move_uploaded_file\(`, `\$_FILES`, `copy\(.*\$_`, `file_put_contents.*\$_`

**Node.js 检查项**
- multer `dest` 配置直接保存 + `originalname` 信任
- `formidable` 默认无大小限制
- `express-fileupload` 默认 `safeFileNames: false`、`preserveExtension: true`
- `path.join(__dirname, req.file.originalname)` 路径穿越
- `unzipper` / `adm-zip` 解压未校验路径
- Grep: `multer\(`, `formidable`, `express-fileupload`, `\.originalname`, `unzipper`, `adm-zip`

**Python 检查项**
- Flask: `request.files['file'].save(path)` 文件名信任
- Django: `request.FILES['file']` + `default_storage.save()` 直接拼路径
- 缺 `werkzeug.utils.secure_filename()`
- `zipfile.extractall()` 不校验路径（Python < 3.6.2 默认 Zip Slip）
- `tarfile.extractall()` 当前版本仍有 Zip Slip 风险
- `PIL.Image.open(stream)` 处理上传图片 → DoS / decompression bomb
- Grep: `request\.files\[`, `request\.FILES\[`, `\.save\(.*filename`, `extractall\(`, `secure_filename`, `Image\.open\(`

**Go 检查项**
- `r.FormFile("file")` + `header.Filename` 直接使用
- `io.Copy(dst, file)` 无大小限制 (DoS)
- `archive/zip` 解压未校验 `f.Name` 前缀
- 缺 `r.Body = http.MaxBytesReader(w, r.Body, maxSize)`
- Grep: `FormFile\(`, `header\.Filename`, `archive/zip`, `MaxBytesReader`

**Ruby 检查项**
- Rails ActiveStorage 默认安全，但 `params[:file].original_filename` 拼接危险
- `Tempfile` + `FileUtils.mv(tmp, user_path)` 路径用户可控
- CarrierWave 自定义 `store_dir` 用户可控
- `Zip::File.open` 解压未校验路径
- Grep: `original_filename`, `params\[:.*file`, `FileUtils\.mv`, `Zip::File`

**Rust 检查项**
- `multipart` crate 处理时 `field.file_name()` 直接使用
- `actix-multipart` 缺大小限制
- `zip` crate 解压未校验路径
- Grep: `multipart`, `file_name\(\)`, `MultipartForm`, `actix-multipart`

**通用加固检查清单**

```
✅ 文件名重命名为 UUID/GUID（杜绝路径穿越和扩展名问题）
✅ 扩展名白名单（不是黑名单）
✅ 服务端检测真实 MIME（魔数 magic bytes，前 4-8 字节）
✅ 文件大小限制（Web 配置 + 代码层双重）
✅ 上传目录与 Web 根目录分离（或目录禁脚本执行）
✅ 上传目录禁解析（.htaccess / web.config / Nginx location）
✅ 图片二次渲染（防御 polyglot）
✅ 解压前校验路径前缀 + 限制解压总大小（防 Zip Bomb）
✅ 病毒扫描（ClamAV 等）
✅ 内容隔离 CDN / Object Storage（不同域 + Content-Disposition: attachment）
✅ CSRF 保护
```

**Grep 速查清单（跨语言）：**
```
# 文件名直接信任
\.FileName|getOriginalFilename|originalname|original_filename|header\.Filename
\$_FILES\[.*\]\[.name.\]|request\.files\[|request\.FILES\[
# 危险保存
move_uploaded_file|SaveAs\(|file_put_contents.*\$_|FileUtils\.mv
# 危险解压
ZipEntry|ZipArchive|extractall\(|adm-zip|unzipper|archive/zip
# 缺少加固
secure_filename|MaxBytesReader|RequestSizeLimit|MaxRequestBodySize
# 解析漏洞配置
AddHandler.*php|\.php5|\.phtml|\.phar|\.aspx?\;
```

**.NET 文件上传攻击链示例（必须识别）：**

| 链路 | 步骤 | 严重性 |
|------|------|------|
| **Chain F** | 上传 .aspx 到 wwwroot/uploads/ → 直接访问执行 → RCE | Critical 9.8 |
| **Chain G** | 上传 web.config 到任意可写目录 → 改变 IIS 行为 → RCE | Critical 9.8 |
| **Chain H** | 上传 .cshtml 到 Razor 编译目录 → 触发编译 → RCE | Critical 9.8 |
| **Chain I** | Zip Slip 覆盖 appsettings.json → 改连接字符串指向攻击者 DB → 凭据窃取 | Critical 9.0 |
| **Chain J** | 上传 SVG 含 onclick → 通过预览触发存储 XSS → 接管管理员 | High 8.0 |

#### Category 22: Email Header Injection (CWE-93)

- User input in email headers (To, CC, BCC, Subject) without CRLF sanitization
- Python: `send_mail(subject=user_input, ...)`, `EmailMessage` with unsanitized fields
- PHP: `mail($to, $subject, $message, $headers)` with user-controlled headers
- Java: `MimeMessage.setSubject(userInput)`, `addRecipient` from user input
- Ruby: `ActionMailer` with user-controlled headers
- Grep: `send_mail(`, `mail(`, `MimeMessage`, `setSubject(`, `ActionMailer`
- Attack: `attacker@evil.com\r\nBcc: victim-list@evil.com`

#### Category 24: Authentication & Authorization Deep Bypass (CWE-287, CWE-269, CWE-639) ⚠️ 高危

**专门覆盖"前台→后台→管理员"的提权链路。这是企业渗透测试中最常被利用的漏洞类别。**

##### 24.1 前台无认证提权（任何人可利用）

**A. 注册接口提权**
- Mass Assignment 注册时传 `role=admin` / `isAdmin=true` / `userType=2`
- 注册接口未校验邮箱域（攻击者注册 `admin@company.com` 通过域名提权）
- 默认账号未禁用：`admin/admin`、`test/test`、`root/root`、`guest/guest`
- 注册时调用了内部 service 跳过角色校验
- Grep: `register|signUp`, 检查接收的字段中是否包含 `role`/`isAdmin`/`type`/`level`/`groupId`

**B. SSO / OAuth / OIDC 漏洞**
- `state` 参数缺失或不校验 → CSRF 绑定攻击者账号
- `redirect_uri` 白名单不严（前缀匹配、子串匹配、open redirect 链）
- `code` 可重放（多次兑换 token）
- ID Token 不校验签名 / 不校验 `aud` / `iss` / `exp`
- PKCE 缺失（移动端、SPA）
- Implicit Flow 在敏感场景仍在使用
- 第三方 IDP 邮箱直接信任（攻击者用未验证邮箱的 IDP 接管账号）
- `nonce` 缺失导致 token 重放
- Grep: `oauth|oidc|sso|callback`, `redirect_uri`, `state\s*=`, `code\s*=`, `id_token`, `nonce`

**C. JWT 高级漏洞**
- `alg: none` 接受
- HS256 ↔ RS256 算法混淆（用公钥当 HMAC key 签名）
- `kid` SQL 注入 / 路径穿越（指向 `/dev/null` 等可预测内容）
- `jku` / `x5u` 任意 URL（攻击者控制 JWKS 端点）
- `jwk` 头嵌入攻击者公钥
- 弱密钥暴破（HS256 密钥 < 32 字节、字典）
- 跨服务密钥复用
- Refresh token 不旋转、不绑定设备
- Grep: `JWT|jsonwebtoken|System\.IdentityModel|Microsoft\.IdentityModel`, `alg|kid|jku|x5u|jwk`, `verify|sign`

**D. 密码重置漏洞**
- Token 可预测（时间戳、自增 ID、低熵 random）
- Token 不绑定用户 ID（IDOR：拿自己 token 改别人密码）
- Token 不过期、不一次性消费
- 重置链接通过 `Host` 头构造 → Host header poisoning（钓鱼链接发到攻击者域名但邮件来自官方）
- 旧密码不校验直接改（CSRF 提权）
- 重置流程中泄露用户存在性（`用户不存在` 提示）
- Grep: `forgot|reset|recover.*password`, `Token`, `Host`, `Url\.Action`

**E. 短信 / 邮件验证码绕过**
- 验证码在响应包内返回（前端校验）
- 验证码不消费可重用
- 验证码可爆破（无频次限制）
- 验证码可绕过（请求中删除验证码字段、传空字符串）
- 同一手机号短时间内可触发多次发送（短信轰炸 → 业务伤害）
- Token 复用（A 手机号的验证码绑到 B）
- Grep: `verifyCode|otpCode|smsCode|captcha`, `redis|cache.*code`

**F. 登录绕过**
- SQL 注入登录：`' OR '1'='1`
- LDAP 注入登录：`*)(uid=*))(|(uid=*`
- 万能密码（程序硬编码）
- Cookie/Session 可预测
- "Remember Me" Token 可伪造
- 多步登录可跳步（直接 POST 第二步绕过 MFA）
- Grep: `login|signIn|authenticate`, 检查参数是否拼接到 SQL/LDAP

**G. 路由 / 中间件绕过**
- HTTP Verb Tampering：POST 改 GET 绕过 `[Authorize]`
- 大小写绕过：`/Admin/users` vs `/admin/users`
- 双 URL 编码：`/admin/%252e%252e/user`
- `;jsessionid=`、`;.html` 后缀绕过路由匹配
- `X-Forwarded-For` / `X-Real-IP` 绕过 IP 白名单
- `X-Original-URL` / `X-Rewrite-URL` 绕过 IIS / Symfony 路由
- 反向代理路径混淆（Nginx `merge_slashes off` + 后端处理差异）
- Spring Cloud Gateway / Spring Boot Actuator 路径穿越（CVE-2022-22947 等）
- ASP.NET Core 路径标准化绕过
- Grep: `excludePathPatterns|skipPath|UrlPathHelper`, `X-Forwarded|X-Original|X-Rewrite`

**H. 信息泄露 → 提权**
- `.git` / `.svn` / `.DS_Store` / `.idea` 暴露
- `.env` / `.env.bak` / `.env.dev` / `appsettings.Development.json` 暴露
- `web.config` / `web.config.bak` 直接下载
- `swagger.json` / `openapi.json` 公开（暴露内部 API + 隐藏端点）
- Spring Boot Actuator (`/actuator/env`、`/heapdump`) 公开
- .NET 9 Health Check 端点 (`/health/details`)
- gRPC Reflection 公开
- GraphQL Introspection 公开
- Source map (`.js.map`) 暴露源码
- 错误堆栈泄露（文件路径、SQL、连接字符串）
- HTTP TRACE 方法启用（XST）
- Grep（在 web 资源访问层）: `\.git|\.svn|\.env|\.bak|swagger|openapi|actuator|heapdump|map$`

##### 24.2 后台普通用户提权（登录后）

**A. 水平越权（IDOR）**
- 查询接口 `userId` 参数可改：`/api/order?userId=2`
- 自增 ID 直接暴露：`/api/profile/123` 可枚举
- 资源 ID 是 GUID 但前端能看到他人 GUID（列表泄露）
- 文件下载：`/api/file?path=user_a/secret.pdf` 可改 path
- 关联资源越权：自己有订单 X，但订单 X 的发票/物流可访问任意订单
- Grep: 控制器中所有 `params/Query/Body` 取 `userId|orgId|tenantId|customerId` 的地方，必须二次校验所有权

**B. 垂直越权**
- `Authorize` 缺失（接口直接公开）
- `Authorize` 但未限定角色 → 普通用户访问 admin 接口
- 同一控制器，部分方法标 `[Authorize(Roles="Admin")]`，部分继承默认
- 配置文件 `[Authorize]` 但路由不匹配（typo 等）
- 权限校验在前端做、后端不做
- Mass Assignment 改 `role`/`isAdmin` 字段提权
- Grep（.NET）: `\[AllowAnonymous\]`, `\[Authorize\]`, `RequireAuthorization`, `User\.IsInRole`
- Grep（Java）: `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `permitAll`
- 必须扫所有 Controller，对比 Phase 1 Endpoint Authentication Matrix

**C. JWT/Cookie 修改提权**
- JWT payload 可解码后改 `role` 字段，重签（弱密钥）
- Cookie 直接改 `IsAdmin=1`（未签名、未加密）
- Session 数据存客户端可篡改

**D. 多租户越权**
- 多租户 SaaS 中 `tenantId` 参数可改
- 数据库查询缺 tenant filter（`WHERE id=?` 而非 `WHERE id=? AND tenant_id=?`）
- 跨租户共享缓存（用户 ID 当 cache key 但未含 tenant ID）
- 子域名信任（`a.saas.com` 用户 cookie 在 `b.saas.com` 生效）

##### 24.3 管理后台 → 系统层 RCE

**A. SQL 注入到 RCE**
- MSSQL `EXEC xp_cmdshell` / `sp_OACreate`
- MySQL UDF / `INTO OUTFILE '/var/www/html/shell.php'`
- PostgreSQL `COPY ... FROM PROGRAM 'curl ...'`
- Oracle `DBMS_SCHEDULER.create_job`
- 检查管理后台 SQL 注入接口是否连接到 SQL Server / MySQL 高权限账号

**B. 任意文件写**
- 写 webshell：`.aspx`/`.cshtml`/`.jsp`/`.php` 到 web 目录
- 写定时任务：cron / Windows 计划任务
- 写配置：改连接字符串到攻击者 DB → 收集凭据
- 写 SSH key：`~/.ssh/authorized_keys`

**C. 反序列化到 RCE**
- 后台导入功能反序列化用户上传文件
- 后台报表/模板配置 反序列化
- 后台缓存写入接口 → Redis Jackson 反序列化

**D. SSRF 打内网**
- 后台爬虫/截图/PDF 生成功能 → SSRF
- 打 169.254.169.254 拿云元数据 token → 接管整个云账号
- 打内网 Redis 6379 → 写 webshell / SSH key
- 打内网 Eureka / Nacos / Consul 注入恶意服务

**Grep（管理后台高危功能）：**
- 文件管理：`upload|download|copy|move|delete|rename`
- 系统管理：`exec|shell|ping|nslookup|traceroute|whoami`
- 数据导入：`import|export|backup|restore|migrate`
- 模板渲染：`template|render|preview`
- 计划任务：`cron|schedule|task`
- 自定义查询：`sql|query|customQuery|dataSource`

#### Category 25: Modern Protocol & Infrastructure Vulnerabilities ⚠️ 高危

##### 25.1 WebSocket
- WebSocket 缺鉴权（`MapHub` / `addEndpoint` 无 `[Authorize]`）
- CSWSH (Cross-Site WebSocket Hijacking)：缺 Origin 校验
- WebSocket 路径未授权（`/ws/admin` 未鉴权）
- 消息内容反序列化（Json.NET TypeNameHandling、Java ObjectInputStream）
- Grep: `WebSocket|MapHub|addEndpoint|@ServerEndpoint|ws://|wss://`

##### 25.2 GraphQL
- Introspection 公开（生产环境暴露所有 schema）
- Query 嵌套 DoS（`user { posts { author { posts { ... } } } }`）
- Batching 攻击（一次请求 1000 个 mutation 绕过限速）
- Field-level 鉴权缺失（list 接口能拿到 admin 字段）
- Alias 滥用爆破登录
- Grep: `graphql|graphene|hot-chocolate|GraphQLSchema|@Query|@Mutation`

##### 25.3 gRPC
- Reflection 启用（`AddGrpcReflection`、`reflection.Register`）
- 未启用 TLS（明文 metadata 含 token）
- Metadata 注入（信任客户端 metadata 中的 user_id）
- 拦截器鉴权缺失
- Grep: `Grpc|grpc-go|grpc-java`, `Reflection|UseInsecure`

##### 25.4 消息队列
- Kafka/RabbitMQ/RocketMQ 默认账号 / 未鉴权
- 消息体反序列化漏洞（Jackson、fastjson）
- Topic / Queue 名称用户可控（注入到不该的 topic）
- 消息签名缺失（攻击者投递伪造消息触发后端流程）
- Grep: `Kafka|Rabbit|RocketMQ|ActiveMQ`, `Producer|Consumer|@KafkaListener`

##### 25.5 缓存
- Redis 公网未授权（6379 暴露 + `requirepass` 未设）
- Redis 主从复制 RCE / `lua_eval` RCE
- Memcached 命令注入（key 含 `\r\n`）
- Web Cache Poisoning（unkeyed header 影响响应）
- Web Cache Deception（`/account.css` 实际命中 `/account` 但被缓存为 css）
- Grep: `redis|StackExchange\.Redis|Lettuce|Jedis|memcached`, `auth|password`

##### 25.6 HTTP 协议层
- HTTP Request Smuggling (CL.TE / TE.CL / TE.TE / HTTP/2 Smuggling)
- Host Header Poisoning（影响密码重置链接、缓存 key）
- HTTP Method Override (`X-HTTP-Method-Override`)
- HTTP/2 → HTTP/1.1 降级攻击
- Connection: keep-alive 影响下游

##### 25.7 DNS
- DNS Rebinding 攻击 SSRF 防护（首次解析合法 IP，后续解析内网 IP）
- 子域名接管（CNAME 指向已删除的云资源）
- Grep: `Dns\.GetHostAddresses|InetAddress\.getByName|gethostbyname`

##### 25.8 容器 / CI/CD
- Docker socket (`/var/run/docker.sock`) 暴露给容器 → 容器逃逸
- Kubernetes Service Account token 泄露
- Helm chart values 注入
- GitHub Actions `pull_request_target` 权限提升
- GitLab CI `if: $CI_PIPELINE_SOURCE` 配置错误
- Webhook 缺签名验证（GitHub/GitLab/支付）
- Grep: `docker\.sock|serviceAccount|pull_request_target|webhook.*secret`

##### 25.9 LLM / AI 应用
- Prompt Injection（用户输入污染 system prompt）
- 工具调用 RCE（LLM 输出被直接 exec）
- SSRF via tool use（LLM 调用 fetch 工具）
- 数据外泄（embedded secrets 被 LLM 复述）
- Grep: `OpenAI|Anthropic|LangChain|LlamaIndex`, `system.*prompt|tool.*call|function.*call`

##### 25.10 客户端
- `postMessage` 缺 origin 校验
- CSP `unsafe-inline`/`unsafe-eval`/`*` 通配
- Service Worker 投毒（缓存恶意脚本）
- localStorage/sessionStorage 存敏感数据（XSS 后被盗）
- Grep: `postMessage|onmessage`, `Content-Security-Policy`, `serviceWorker|register`, `localStorage|sessionStorage`

#### Category 26: Privilege Escalation Patterns（提权链路库）

**这是 Phase 3.7 攻击链构造的输入库。每个模式都是被验证过的真实提权路径。**

| 链路 ID | 入口 | 步骤 | 终态 |
|--------|------|------|-----|
| **PE-1** | 注册 + Mass Assignment | 注册时传 `role=admin` | 直接管理员 |
| **PE-2** | 默认凭据 | 字典爆破 admin/admin | 直接管理员 |
| **PE-3** | JWT 弱密钥 | 暴破 HS256 密钥 → 改 role 重签 | 任意身份 |
| **PE-4** | JWT alg 混淆 | RS256 → HS256（公钥当 HMAC key） | 任意身份 |
| **PE-5** | OAuth state 缺失 | 钓鱼链接绑定攻击者账号到受害者 | 接管受害者 |
| **PE-6** | 密码重置 IDOR | 自己拿 token，改 user_id | 接管任意 |
| **PE-7** | 验证码爆破 | 手机号 + 4 位验证码无频次 | 任意账号登录 |
| **PE-8** | 路由绕过 + 后台 SQL 注入 | `/Admin/users` 大小写绕过 | 数据 dump |
| **PE-9** | Actuator/env + Redis Jackson | 拿 Redis 凭据 → 写 Jackson payload | RCE |
| **PE-10** | 上传 .config + IIS 解析 | 上传 web.config 改 handler | RCE |
| **PE-11** | SSRF 169.254.169.254 | 云元数据拿 IAM token | 接管云账号 |
| **PE-12** | DNS Rebinding 绕过 SSRF 防护 | 首次 1.1.1.1，第二次 169.254.169.254 | 接管云账号 |
| **PE-13** | XXE 读 web.config + 数据库 | 拿 SQL 凭据 → DB 提权 | RCE |
| **PE-14** | Swagger 暴露 + 隐藏接口 | 找到未鉴权 admin 接口 | 直接管理员 |
| **PE-15** | Webhook 无签名 | 伪造支付回调 | 业务提权 |
| **PE-16** | postMessage XSS + token 窃取 | 父页面 XSS 偷子页 token | 接管账号 |
| **PE-17** | GraphQL field-level 缺鉴权 | 查 list 接口拿 admin 字段 | 提权 |
| **PE-18** | Race Condition 充值 | 并发触发 → 余额翻倍 | 业务提权 |
| **PE-19** | gRPC Reflection 暴露 | 列出所有方法找未鉴权方法 | 后台提权 |
| **PE-20** | Web Cache Deception | `/account/info.css` 缓存敏感 | 信息泄露 |

**Phase 3.7 攻击链构造时，必须遍历此表，对每个匹配的入口尝试构造完整链路。**

### Phase 3: Dependency & Supply Chain Analysis

**Dependency files by language:**
- Go: `go.mod`, `go.sum`
- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `uv.lock`
- JavaScript/TypeScript: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`, `*.jar` versions
- PHP: `composer.json`, `composer.lock`
- Ruby: `Gemfile`, `Gemfile.lock`
- Rust: `Cargo.toml`, `Cargo.lock`
- C#/.NET: `*.csproj`, `packages.config`, `nuget.config`

**Supply chain attack vectors:**
- Known CVE in direct or transitive dependencies
- Typosquatting (e.g., `lodash` vs `1odash`, `requests` vs `request`)
- Dependency confusion (internal package name collision with public registry)
- Malicious preinstall/postinstall scripts (npm)
- Pinned vs unpinned versions (use lockfiles!)
- Abandoned/unmaintained packages with unpatched vulns
- Git submodules pointing to external repos (check commit pinning)
- Docker base image vulnerabilities (`FROM` directive check)

### Phase 4: Language-Specific Deep Analysis

Detect the target language(s) and perform language-specific deep analysis:

#### Go Deep Analysis
- `unsafe.Pointer` usage and unsafe arithmetic
- Missing error handling (`_` for errors)
- Goroutine leaks (goroutines without cancellation)
- Context cancellation not propagated
- HTTP handler without timeout (`http.Server` missing `ReadTimeout`/`WriteTimeout`)
- Missing `defer resp.Body.Close()`
- SQL connection pool exhaustion
- Template injection: `text/template` (no escaping) vs `html/template`
- `cgo` boundary: memory safety issues at Go/C boundary
- Grep: `unsafe.Pointer`, `//go:nosplit`, `//go:noescape`, `cgo`, `C.`, `text/template`

#### Java Deep Analysis
- **Spring-specific**: SpEL injection via `@Value("#{}")`, `@PreAuthorize` with user input
- **Deserialization chains**: commons-collections, commons-beanutils, Spring gadgets, Jackson polymorphic typing
- **JNDI injection**: `InitialContext.lookup()`, Log4Shell (`${jndi:ldap://}`)
- **XXE in all XML parsers**: DocumentBuilderFactory, SAXParser, XMLReader, StAX, XStream
- **Struts OGNL injection**: `ActionSupport`, OGNL expressions in tags
- **MyBatis**: `${}` interpolation (vulnerable) vs `#{}` parameterized (safe) — scan BOTH XML mapper files (`.xml` in `mapper`/`dao` directories) AND `@Select`/`@Update`/`@Delete`/`@Insert` annotations in Java for `${}`. Dangerous patterns: `ORDER BY ${column}`, `LIKE '%${keyword}%'`, `IN (${ids})`, `${tableName}`, `${signSql}` (entire SQL fragment injection)
- **Reflection abuse**: `Class.forName()`, `Method.invoke()` with user input
- **File upload**: `MultipartFile.getOriginalFilename()` without sanitization
- **fastjson/Jackson**: autoType exploits, polymorphic deserialization
- **Jackson enableDefaultTyping RCE**: `ObjectMapper.enableDefaultTyping()` or `activateDefaultTyping()` — CRITICAL when used in Redis/MQ/RPC serializers. Check `NON_FINAL` parameter. Grep ALL ObjectMapper instances and trace if `enableDefaultTyping` is called, even in @Configuration classes. Combined with gadget chains (commons-collections, c3p0, groovy) this enables RCE via crafted JSON.
- **XXL-Job executor exploitation**: If `xxl-job-core` in dependencies: (a) check `accessToken` — empty or hardcoded = unauthenticated job submission, (b) executor `/run` accepts `GLUE_SHELL`/`GLUE_GROOVY` = arbitrary code execution, (c) check executor port (default 9999) network exposure. Token leaked via Actuator /env = chained zero-auth RCE.
- **Druid monitoring console**: If `druid-spring-boot-starter` in dependencies: (a) check `StatViewServlet` registration, (b) `loginUsername`/`loginPassword` — defaults often `admin/admin` or hardcoded, (c) `allow` IP filter empty = all IPs, (d) SQL monitoring page leaks query parameters. Wall filter disabled = no SQL restriction.
- Grep: `ObjectInputStream`, `readObject()`, `Class.forName(`, `InitialContext`, `lookup(`, `@Value("#{`, `\${`, `OGNL`, `fastjson`, `autoType`, `enableDefaultTyping`, `activateDefaultTyping`, `XxlJobSpringExecutor`, `accessToken`, `StatViewServlet`, `loginUsername`

#### Python Deep Analysis
- **eval/exec/compile**: Code injection via `eval()`, `exec()`, `compile()` with user input
- **pickle/marshal/shelve**: Deserialization RCE via `pickle.loads()`, `marshal.loads()`, `shelve.open()`
- **YAML**: `yaml.load()` without `Loader=SafeLoader` (RCE via `!!python/object`)
- **subprocess**: `shell=True` with user input, `shlex` misuse
- **Django-specific**: `extra()`, `RawSQL()`, `|safe` template filter, `@csrf_exempt`, `DEBUG=True`
- **Flask-specific**: `render_template_string(user_input)`, debug mode, secret key hardcoded
- **SQLAlchemy**: `text()` with string formatting, raw execute with f-strings
- **Format string**: `str.format()` with user-controlled format string (attribute access via `{0.__class__}`)
- **`__import__`**: Dynamic import with user input
- **`os.path.join` gotcha**: Absolute path in later arg overrides base
- Grep: `eval(`, `exec(`, `compile(`, `pickle`, `yaml.load`, `shell=True`, `render_template_string`, `extra(`, `RawSQL`, `|safe`, `DEBUG.*True`, `SECRET_KEY`

#### TypeScript/JavaScript/Node.js Deep Analysis
- **Prototype pollution**: `__proto__`, `constructor.prototype` manipulation in deep merge
- **eval/Function**: `eval(userInput)`, `new Function(userInput)`, `setTimeout(string)`
- **child_process**: `exec(cmd)` (shell), `execSync(cmd)`, `spawn` with `shell: true`
- **Express-specific**: Missing helmet, CORS `origin: true`, body parser limits
- **npm/yarn**: Typosquatting, preinstall/postinstall scripts in dependencies
- **MongoDB injection**: `$gt`, `$ne`, `$regex` operators from req.body/req.query
- **Template engines**: `ejs.render(userInput)`, `pug.render(userInput)`, `Handlebars.compile(userInput)`
- **Path traversal**: `path.join(base, req.params.file)` without `path.resolve` + validation
- **JWT**: `jsonwebtoken` with `algorithms: ['none']`, `HS256` with weak secret
- **ReDoS**: Complex regex on user input (Node.js uses backtracking V8 regex)
- **Denial of Service**: Missing rate limiting, no request size limits, event loop blocking
- Grep: `eval(`, `Function(`, `child_process`, `exec(`, `execSync(`, `shell:`, `__proto__`, `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `\$gt`, `\$ne`, `\$regex`

#### PHP Deep Analysis
- **Remote Code Execution**: `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, backtick operator
- **eval/include injection**: `eval($_GET)`, `include($_GET['page'])`, `require($var)`, `preg_replace` with `/e` modifier
- **Type juggling**: `==` comparison (loose) allowing `"0" == false == null`, `strcmp()` bypass with arrays
- **Deserialization**: `unserialize()` with user input (POP chain exploitation), `phar://` deserialization trigger
- **Variable variables**: `$$var` — user controls variable name
- **File inclusion**: `include()`, `require()`, `include_once()`, `require_once()` with user path, `php://` wrapper abuse
- **SQL injection**: `mysql_query("...{$_GET['id']}")`, PDO without prepared statements
- **XXE**: `simplexml_load_string()`, `DOMDocument::loadXML()` without disabling entities
- **File upload**: Missing MIME validation, `.php` extension bypass (`.php5`, `.phtml`, `.phar`)
- **Session fixation**: `session_id($_GET['sid'])`
- **Open basedir bypass**: Symlink tricks, `glob://` wrapper
- **Dangerous functions**: `assert()` (code execution in PHP5), `create_function()`, `call_user_func()`
- Grep: `system(`, `exec(`, `passthru(`, `shell_exec(`, `popen(`, `eval(`, `include(`, `require(`, `unserialize(`, `preg_replace.*\/e`, `\$\$`, `assert(`, `create_function(`, `call_user_func(`, `mysql_query(`

#### Ruby Deep Analysis
- **Command injection**: `system(userInput)`, `exec(userInput)`, backticks, `IO.popen(userInput)`, `Open3.capture3(userInput)`, `Kernel.send(:system, userInput)`
- **ERB SSTI**: `ERB.new(user_input).result`
- **Mass assignment**: Missing `strong_parameters` (`.permit()`), `attr_accessible` bypass
- **Deserialization**: `Marshal.load(user_data)`, `YAML.load(user_data)` (Psych < 4.0)
- **SQL injection**: `where("name = '#{params[:name]}'")`, `find_by_sql(user_input)`
- **Open redirect**: `redirect_to(params[:url])`
- **Dynamic dispatch**: `send(params[:method])`, `public_send(params[:action])` — calls arbitrary methods
- **File operations**: `File.read(params[:path])`, `send_file(params[:file])`
- **Regex DoS**: Ruby regex uses backtracking (no RE2 by default)
- **Dependency confusion**: Gemfile source manipulation
- Grep: `system(`, `exec(`, `IO.popen(`, `Open3`, `send(`, `public_send(`, `ERB.new(`, `Marshal.load(`, `YAML.load(`, `find_by_sql(`, `where("`, `redirect_to(`, `send_file(`

#### Rust Deep Analysis
- **unsafe blocks**: Raw pointer dereference, transmute, pointer arithmetic
- **FFI boundary**: Memory safety issues at Rust/C boundary via `extern "C"`
- **Send/Sync violations**: Incorrect `unsafe impl Send/Sync` for types with interior mutability
- **Integer overflow**: Debug vs release build behavior difference (panic vs wrap)
- **Panic in FFI**: Unwinding across FFI boundary is UB
- **Use-after-free via unsafe**: `Box::from_raw`, `ManuallyDrop`, `std::mem::forget` misuse
- **Command injection**: `std::process::Command::new("sh").arg("-c").arg(user_input)`
- **SQL injection**: `sqlx::query(format!("SELECT ... {}", user_input))`
- **Path traversal**: `std::fs::read_to_string(user_path)` without canonicalize check
- **Deserialization**: `serde_json::from_str` to enum with `#[serde(tag)]` + untrusted input
- Grep: `unsafe`, `transmute`, `from_raw`, `extern "C"`, `ManuallyDrop`, `raw_pointer`, `.arg("-c")`, `format!.*SELECT`

#### C#/.NET Deep Analysis

**SQL Injection (传统 + 现代 ORM)**
- 传统: `SqlCommand("..." + userInput)`, `OleDbCommand`, `SqlDataAdapter`
- LINQ raw SQL: `EF.FromSqlRaw($"...{userInput}")` (危险) vs `FromSqlInterpolated($"...{userInput}")` (参数化安全)
- EF Core: `Database.ExecuteSqlRaw(userInput)`, `Database.SqlQueryRaw<T>()`
- Dapper: `Execute(sql + userInput)`, `Query<T>(sql + userInput)` — 应使用 `@param` + 匿名对象
- 加固识别: `SqlParameter`, `cmd.Parameters.AddWithValue("@id", ...)`, `FromSqlInterpolated`
- Grep: `FromSqlRaw\(`, `ExecuteSqlRaw\(`, `SqlCommand\(.*\+`, `OleDbCommand`, `Dapper.*Execute\(.*\+`

**反序列化 (覆盖现代主流 + 老旧)**
- 危险老式: `BinaryFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, `JavaScriptSerializer`+`TypeNameHandling`
- 危险现代:
  - **Json.NET**: `JsonConvert.DeserializeObject<T>(json, settings)` 当 `settings.TypeNameHandling != None` (CRITICAL)
  - **System.Text.Json**: 多态时未限制 `TypeInfoResolver`、`JsonSerializerOptions.TypeInfoResolverChain`
  - **XmlSerializer** + 用户控制 type
  - **DataContractSerializer** + 未限制 `KnownType`
  - **YamlDotNet** `Deserializer` 默认允许任意类型
  - **MessagePack**: `MessagePackSerializer.Typeless.Deserialize`
  - **protobuf-net**: 配合 `DynamicType`
- ViewState 反序列化: `__VIEWSTATE` 解码、`EnableViewStateMac=false`
- 加固识别: 自定义 `SerializationBinder`、`KnownTypes` 限定、`MaxDepth` 设置、JSON.NET 升级到 13.0+ 默认 None
- Grep: `BinaryFormatter`, `TypeNameHandling[^.]*\.(All|Auto|Objects|Arrays)`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, `YamlDotNet`, `MessagePackSerializer\.Typeless`, `ProtoBuf.*DynamicType`

**SSRF (.NET 专项)** ⚠️ 高危
- `HttpClient.GetAsync(userUrl)`, `HttpClient.PostAsync(userUrl, ...)`, `HttpClient.SendAsync`
- `WebClient.DownloadString(userUrl)`, `WebClient.DownloadData(userUrl)`
- `WebRequest.Create(userUrl)`, `HttpWebRequest.Create(userUrl)`
- `RestClient` (RestSharp) BaseUrl 用户可控
- `Flurl.Url.Get(userUrl)`
- 缺少 URL 白名单、未禁内网 (10/8、172.16/12、192.168/16) 与链路本地 (169.254.169.254 云元数据)
- 加固识别: 白名单 host 校验、`IPAddress.IsLoopback`/`IsInSubnet`、`Uri.HostNameType` 校验、DNS rebinding 防护
- Grep: `HttpClient.*\.(Get|Post|Send)Async\(`, `WebClient.*\.Download`, `WebRequest\.Create\(`, `HttpWebRequest`, `RestClient`, `Flurl`

**XXE (扩展)**
- `XmlDocument.Load()` 默认 `XmlResolver != null`（.NET Framework < 4.5.2 不安全）
- `XmlReader.Create()` 配 `DtdProcessing.Parse` 或 `XmlResolver`
- `XmlSerializer` 处理外部 XML
- `XPathDocument` 读取不可信 XML
- 加固识别: `DtdProcessing = DtdProcessing.Prohibit`, `XmlResolver = null`, `XmlSecureResolver`

**JWT 漏洞 (ASP.NET Core 专项)** ⚠️ 高危
- `TokenValidationParameters.ValidateIssuerSigningKey = false` (CRITICAL)
- `ValidateAudience = false` 且 `ValidateIssuer = false`
- `ValidateLifetime = false` (永久有效 token)
- `SymmetricSecurityKey(Encoding.UTF8.GetBytes("hardcoded"))` (硬编码密钥)
- 密钥长度 < 32 字节 (HS256 暴破)
- `RequireSignedTokens = false`
- 接受 `alg: none` (老旧 JwtSecurityTokenHandler 配置)
- Grep: `ValidateIssuerSigningKey\s*=\s*false`, `ValidateLifetime\s*=\s*false`, `SymmetricSecurityKey\(`, `Encoding\.UTF8\.GetBytes\(.*[Kk]ey`, `RequireSignedTokens\s*=\s*false`

**Razor / Blazor / WebView2 (扩展)**
- 动态 Razor: `RazorEngine.Compile(userInput)`, `RazorLight.CompileRenderStringAsync`
- `@Html.Raw(userInput)` (XSS)
- `IHtmlContent` 实现绕过编码
- Blazor: `@((MarkupString)userInput)`, `JSRuntime.InvokeAsync<string>("eval", userInput)`
- WebView2: `ExecuteScriptAsync(userInput)`, `AddHostObjectToScript` 暴露 .NET 对象给 JS
- Grep: `@Html\.Raw\(`, `MarkupString`, `RazorEngine`, `CompileRenderStringAsync`, `ExecuteScriptAsync\(`, `AddHostObjectToScript`

**LDAP 注入**
- `DirectorySearcher.Filter = "(uid=" + userInput + ")"`
- `DirectoryEntry` path 拼接
- 加固: 自定义 LDAP filter encoder（OWASP 推荐转义 `\*()\` 等字符）

**命令执行 (扩展)**
- `Process.Start("cmd", "/c " + userInput)`, `Process.Start(new ProcessStartInfo { Arguments = ... })`
- `PowerShell.Create().AddScript(userInput).Invoke()` (RCE，常被忽略)
- `Runspace.Open()` + `Pipeline.Commands.AddScript(userInput)`
- WMI 注入: `ManagementObjectSearcher(query + userInput)`
- Grep: `Process\.Start\(`, `PowerShell\.Create\(`, `AddScript\(`, `Runspace\.Open\(`, `ManagementObjectSearcher`

**加密误用 (.NET 专项)**
- `MD5.HashData`, `SHA1.HashData` 用于密码场景
- `Rfc2898DeriveBytes(password, salt, iterations=1000)` — OWASP 2023 要求 ≥ 600,000
- `RijndaelManaged` ECB 模式、硬编码 IV
- `RandomNumberGenerator` vs `System.Random` (后者非密码学安全，禁用于 token/密码生成)
- TLS 验证关闭 (CRITICAL):
  - `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true`
  - `HttpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`
- `MachineKey` 硬编码、跨应用复用
- Grep: `MD5\.|SHA1\.`, `Rfc2898DeriveBytes\(.*,\s*\d{1,5}\s*\)`, `\bECB\b`, `ServerCertificateValidationCallback`, `DangerousAcceptAnyServerCertificate`, `new Random\(\)`

**WCF 旧服务**
- `NetDataContractSerializer` 反序列化 (CRITICAL)
- `<security mode="None">` binding 配置
- WSDL 外部暴露
- Grep: `NetDataContractSerializer`, `<security mode="None"`, `NetTcpBinding.*Security`

**Office/Excel 文件解析**
- NPOI 解析上传 .xls/.xlsx 时未禁用外部链接
- EPPlus `ExcelPackage(stream)` 处理 .xlsm 宏 (DDE/外部公式)
- OpenXML 读取未禁 DTD
- Grep: `NPOI\.`, `ExcelPackage\(`, `WordprocessingDocument\.Open\(`

**ASP.NET Core 配置错误（汇总，详细见 Phase 3.8）**
- `app.UseDeveloperExceptionPage()` 生产环境开启
- CORS: `AllowAnyOrigin().AllowCredentials()`
- Cookie `SameSite=None` + `Secure=false`
- 缺 `app.UseHttpsRedirection()` / `UseHsts()`
- gRPC: `services.AddGrpcReflection()` 生产暴露
- SignalR Hub 无 `[Authorize]`
- Minimal API 路由参数未类型校验

**基础项 (沿用 v3.0)**
- **路径穿越**: `File.ReadAllText(Path.Combine(basePath, userInput))` 缺 canonicalize
- **开放重定向**: `Redirect(Request.QueryString["url"])` 缺白名单
- **CSRF**: POST 缺 `[ValidateAntiForgeryToken]`
- **Mass Assignment**: `TryUpdateModel(user)` 缺 `[Bind]`
- **ReDoS**: .NET regex 默认回溯，需设 `RegexOptions.NonBacktracking` (.NET 7+) 或 `MatchTimeout`

**整体 Grep 速查清单**:
```
# 反序列化
BinaryFormatter|ObjectStateFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter
TypeNameHandling[^.]*\.(All|Auto|Objects|Arrays)
YamlDotNet|MessagePackSerializer\.Typeless|ProtoBuf.*DynamicType
# SQL
FromSqlRaw\(|ExecuteSqlRaw\(|SqlCommand\(.*\+|Dapper.*Execute\(.*\+
# SSRF
HttpClient.*(Get|Post|Send)Async\(|WebClient.*Download|WebRequest\.Create\(|RestClient|Flurl
# JWT
ValidateIssuerSigningKey\s*=\s*false|ValidateLifetime\s*=\s*false
SymmetricSecurityKey\(|Encoding\.UTF8\.GetBytes\(.*[Kk]ey
# XXE
DtdProcessing\.Parse|XmlResolver\s*=\s*new
# 命令/PowerShell
Process\.Start\(|PowerShell\.Create\(|AddScript\(|Runspace\.Open\(
# 加密
ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificate
Rfc2898DeriveBytes\(.*,\s*\d{1,5}\s*\)|new Random\(\)|MD5\.|SHA1\.
# Razor / Blazor / WebView
@Html\.Raw\(|MarkupString|RazorEngine|CompileRenderStringAsync
ExecuteScriptAsync\(|AddHostObjectToScript
# 配置
UseDeveloperExceptionPage|AllowAnyOrigin.*AllowCredentials|AddGrpcReflection
```

#### Kotlin/Swift Deep Analysis

**Kotlin (Android/JVM)**
- WebView `addJavascriptInterface()` + `evaluateJavascript()` with user content
- Intent injection: `startActivity(intent)` from untrusted extras
- `Runtime.getRuntime().exec()` with user input
- SQL via Room: `@RawQuery` with string concatenation
- Exported components without permission checks (`android:exported="true"`)
- Grep: `addJavascriptInterface`, `evaluateJavascript`, `startActivity`, `@RawQuery`, `android:exported`

**Swift (iOS)**
- `WKWebView.evaluateJavaScript(userInput)`
- `NSTask`/`Process` with user arguments
- Keychain: storing sensitive data with `kSecAttrAccessibleAlways`
- URL scheme handling without validation
- `NSCoding`/`NSKeyedUnarchiver` deserialization (use `NSSecureCoding`)
- Grep: `evaluateJavaScript`, `NSTask`, `Process(`, `kSecAttrAccessible`, `NSKeyedUnarchiver`

### Phase 5: Report Generation

Generate a structured vulnerability report. Group findings by attack surface (前台 → 后台 → 管理后台 → 组合链), NOT just by severity.

```
## Vulnerability Report

### Executive Summary
- Total findings: X (前台: A | 后台: B | 管理后台: C | 组合链: D)
- Critical: X | High: X | Medium: X | Low: X

### 一、前台漏洞（无需认证，任何人可利用）

#### [VULN-001] Title
- **漏洞位面**: 前台(匿名)
- **严重性**: Critical/High/Medium/Low
- **CWE**: CWE-XXX
- **CVSS**: X.X
- **HTTP 入口**: `METHOD /url/path` (ControllerClass.java:行号)
- **认证要求**: 无需认证 — 原因(permitAll / 拦截器未覆盖 / ...)
- **调用链**: Controller.method() → Service.method() → Mapper/Sink
- **用户可控参数**: 参数名、来源(query/body/header/path)
- **漏洞代码**:
  ```language
  // 漏洞代码片段 (标注危险行)
  ```
- **影响**: 攻击者可以做什么
- **利用方式**: curl/HTTP 请求示例
- **可利用性**: 已验证 / 可利用 / 需条件
- **修复建议**: 具体修复方案
- **修复代码**:
  ```language
  // 修复后代码
  ```

### 二、后台漏洞（需普通用户登录）

(同上格式，漏洞位面改为"后台(普通用户)")

### 三、管理后台漏洞（需管理员权限）

(同上格式，漏洞位面改为"管理后台(管理员)")

### 四、组合攻击链（多漏洞串联提权）

#### [CHAIN-001] Title
- **最终影响**: RCE / 数据泄露 / 账户接管 / ...
- **组合严重性**: Critical 9.8
- **前提条件**: 无需认证 / 需低权限用户 / ...
- **攻击步骤**:
  1. [VULN-X] 前台漏洞 → 获取 xxx
  2. [VULN-Y] 利用 xxx → 访问 yyy
  3. [VULN-Z] 利用 yyy → 实现 RCE/接管
- **利用脚本**: curl 命令或 Python 脚本
- **引用漏洞**: VULN-X, VULN-Y, VULN-Z

### 五、代码质量问题（无 HTTP 入口，不计入漏洞数）

(无法追踪到 HTTP 入口的发现放在这里)

### 六、依赖风险（有 CVE 但无可达代码路径）

(库有 CVE 但应用中无触发路径的放在这里)
```

## Severity Classification (按攻击面调整)

| 漏洞类型 | 前台(匿名) | 后台(普通用户) | 管理后台(管理员) |
|----------|-----------|-------------|---------------|
| RCE / 反序列化 | **Critical** | **Critical** | High |
| SQL 注入 | **Critical** | High | Medium-High |
| 认证绕过 | **Critical** | - | - |
| 任意文件上传 (可执行) | **Critical** | High | Medium |
| SSRF (内网穿透) | **Critical** | High | Medium |
| 硬编码凭据 (admin) | **Critical** | - | - |
| XSS (存储型) | High | Medium | Low |
| 文件读取/下载 | High | Medium | Low |
| 信息泄露 (配置/凭据) | High | Medium | Low |
| CORS 错误配置 | Medium | Low | Low |
| 缺少安全头 | Low | Low | Info |

**组合链提权规则**: 当多个漏洞组合后，整体严重性取最终影响的级别，而非单个漏洞的级别。例如：
- 前台信息泄露(Medium) + 后台 SQL 注入(High) = **组合链 Critical**（前台获取凭据 → 登录 → SQL 注入）
- 前台 JWT 弱密钥(Critical) + 管理后台 RCE(High) = **组合链 Critical**（伪造 admin JWT → RCE）

## Execution Strategy for Large Codebases

For enterprise codebases with 100K+ files:

1. **Prioritize high-risk areas first**:
   - Authentication/login handlers
   - API endpoint handlers (HTTP routers)
   - Database query builders
   - File upload/download handlers
   - External command execution
   - Cryptographic operations

2. **Use targeted grep patterns** to find vulnerability hotspots
3. **Follow data flows** from entry points to sinks
4. **Check configuration files** for secrets and misconfigurations
5. **Sample representative services** rather than scanning every file

### Phase 3.5: Coverage Verification

After all Phase 3 Agents complete, verify coverage by following `scripts/coverage-check.md`:
1. Collect each Agent's coverage declaration (which categories it scanned)
2. Compare against Phase 1 coverage matrix
3. If any applicable category is MISSING → launch a supplementary Agent for those categories only
4. Max 2 rounds of gap-filling to prevent infinite loops
5. Output a coverage summary table for the final report

### Phase 3.6: Configuration Class Deep Scan (Java/Spring)

When the target is a Java/Spring project, perform a dedicated scan of `@Configuration` classes. These set security-critical parameters that individual vulnerability scans often miss.

**Step 1: Locate all configuration classes**
```bash
grep -rl '@Configuration\|@SpringBootApplication\|@EnableWebSecurity' TARGET_DIR/ --include='*.java'
```

**Step 2: Mandatory configuration checks**

| Config Pattern | File Name Hint | What to Check | CWE |
|---------------|----------------|---------------|-----|
| `*RedisConfig*` | RedisConfig, RedissonConfig, CacheConfig | `enableDefaultTyping` / `activateDefaultTyping` on ObjectMapper passed to RedisTemplate → Jackson deserialization RCE | CWE-502 |
| `*CorsConfig*` / `WebMvcConfigurer` | CorsConfig, WebConfig | `allowedOrigins("*")` + `allowCredentials(true)` → credential theft via CORS | CWE-942 |
| `*DruidConfig*` | DruidConfig | `StatViewServlet` with `loginUsername`/`loginPassword` hardcoded or default → monitoring console exposure | CWE-798 |
| `*SecurityConfig*` | SecurityConfig, WebSecurityConfig | `csrf().disable()`, overly broad `permitAll()`, actuator endpoints without auth | CWE-352, CWE-862 |
| `WebAppConfiguration` / `InterceptorConfig` | WebAppConfiguration | `excludePathPatterns` list — what paths bypass auth interceptors (Swagger, actuator, test, druid) | CWE-862 |
| `*XxlJobConfig*` | XxlJobConfig | `accessToken` value — if empty or hardcoded, attackers submit GLUE_SHELL jobs for RCE | CWE-798 |
| `*MailConfig*` / `MailSender` | MailConfig, MailSenderService | `setTrustAllHosts(true)` → TLS bypass; hardcoded SMTP credentials | CWE-295, CWE-798 |
| Actuator config | application.yml/.properties | `management.endpoints.web.exposure.include=*` → env dump, heap dump, credential extraction | CWE-200 |

**Step 3**: If the project uses a library from the table above, the corresponding check is MANDATORY even if no config class is found (the library may use defaults).

### Phase 3.7: Attack Chain Construction

After individual findings are collected, connect related findings into multi-step attack chains. A chain has higher severity than any individual finding.

**Chain construction process:**
1. For each CRITICAL/HIGH finding, check if it can be an entry point (externally reachable, no auth)
2. For each entry point, trace what assets it gives access to (credentials, internal services)
3. For each accessed asset, check if another finding enables escalation (deserialization, code execution)
4. Document the complete path as a single chain finding

**Known chain templates for Java/Spring:**

| Chain | Pattern | Combined Severity |
|-------|---------|-------------------|
| **A** | Actuator /env exposed → extract Redis/DB/MQ credentials → connect to Redis → inject Jackson payload (enableDefaultTyping) → RCE | **Critical 9.8** |
| **B** | Actuator /env exposed → extract XXL-Job accessToken → call executor /run with GLUE_SHELL → RCE | **Critical 9.8** |
| **C** | Hardcoded JWT key in source → forge admin JWT → access admin APIs → full app control | **Critical 9.8** |
| **D** | SQL injection in any endpoint → dump credentials table → access connected services | **Critical 9.0** |
| **E** | Auth interceptor excludePathPatterns too broad → access unprotected endpoint with SSRF/injection → internal network/RCE | **Critical 9.0** |

**Output format:**
```
#### [CHAIN-001] Title
- **Severity**: Critical
- **Steps**: 1. [VULN-X] → 2. [VULN-Y] → 3. RCE
- **Individual findings**: VULN-X, VULN-Y
- **Combined CVSS**: 9.8
```

Upgrade Actuator exposure from Medium/High to CRITICAL when it enables Chain A or B.

### Phase 3.8: Configuration Deep Scan (C#/.NET)

When the target is a C#/.NET project (presence of `*.csproj`, `*.sln`, `Program.cs`, `Startup.cs`), perform a dedicated scan of configuration files and DI registration code. This phase mirrors Phase 3.6 (Java) but targets .NET-specific risks.

**Step 1: Locate all configuration entry points**
```bash
# Modern ASP.NET Core (6+)
find TARGET_DIR -name 'Program.cs' -o -name 'Startup.cs' -o -name 'appsettings*.json'
# Legacy ASP.NET
find TARGET_DIR -name 'web.config' -o -name 'Global.asax*'
# DI configuration classes
grep -rl 'IServiceCollection\|ConfigureServices\|WebApplication.CreateBuilder' TARGET_DIR --include='*.cs'
```

**Step 2: Mandatory configuration checks**

| Config Pattern | File Hint | What to Check | CWE |
|---------------|-----------|---------------|-----|
| **JWT 配置** | Program.cs, Startup.cs, AuthExtensions | `TokenValidationParameters.ValidateIssuerSigningKey=false`, `ValidateAudience=false`, `ValidateLifetime=false`, `SymmetricSecurityKey` 弱密钥(<32字节)，`SigningCredentials` 硬编码 | CWE-347, CWE-798 |
| **CORS 配置** | *Cors*.cs, Program.cs | `AllowAnyOrigin().AllowCredentials()`, `WithOrigins("*")`, `SetIsOriginAllowed(_ => true)` | CWE-942 |
| **Identity 配置** | IdentityConfig | `PasswordOptions` 弱(`RequiredLength<8`)、`Lockout.AllowedForNewUsers=false`、`SignIn.RequireConfirmedEmail=false` | CWE-521 |
| **DataProtection** | DataProtectionConfig | 未配置 `PersistKeysToFileSystem`/`ProtectKeysWithCertificate`，多实例不共享 key 致登录态丢失/可被重放 | CWE-321 |
| **Cookie 安全** | CookieAuthOptions, AddCookie | `Cookie.SameSite=None` + `Secure=false`，`HttpOnly=false`，无 `Cookie.SecurePolicy=Always` | CWE-614, CWE-1004 |
| **Kestrel 限制** | Program.cs | 缺 `Limits.MaxRequestBodySize`、`Limits.MaxConcurrentConnections`、`KeepAliveTimeout` 过长 | CWE-770 |
| **错误页面** | Program.cs | 生产环境暴露 `UseDeveloperExceptionPage()`，无 `UseExceptionHandler` | CWE-209 |
| **Swagger 暴露** | Program.cs | `app.UseSwagger()` + `app.UseSwaggerUI()` 在生产未禁用，泄露 API 结构 | CWE-200 |
| **HTTPS 强制** | Program.cs | 缺 `app.UseHttpsRedirection()`, `app.UseHsts()` | CWE-319 |
| **AntiForgery** | Program.cs | `services.AddControllers()` 缺 `ValidateAntiForgeryTokenFilter` 或控制器缺 `[ValidateAntiForgeryToken]` | CWE-352 |
| **AllowedHosts** | appsettings.json | `"AllowedHosts": "*"` (Host header 攻击/缓存投毒) | CWE-20 |
| **连接字符串** | appsettings*.json, web.config | 硬编码密码，未使用 User Secrets/Key Vault/环境变量 | CWE-798 |
| **customErrors** | web.config | `<customErrors mode="Off">` 生产暴露错误堆栈 | CWE-209 |
| **debug 模式** | web.config | `<compilation debug="true">` 生产环境 | CWE-489 |
| **machineKey** | web.config | `<machineKey>` 硬编码、validationKey/decryptionKey 弱或共享 | CWE-321 |
| **gRPC 反射** | Program.cs | `services.AddGrpcReflection()` 生产暴露所有服务定义 | CWE-200 |
| **SignalR Hub** | *Hub.cs | Hub 类无 `[Authorize]`，`MapHub<T>("/hub")` 公开 | CWE-862 |
| **EF 默认追踪** | DbContext | `QueryTrackingBehavior.NoTracking` 缺失，列表查询 OOM 风险 | CWE-770 |
| **Serilog/NLog Sink** | appsettings.json | 日志 Sink 写公开目录、HTTP Sink 无 TLS、Sink 路径用户可控 | CWE-532 |
| **Health Check 暴露** | Program.cs | `MapHealthChecks("/health")` 无 `RequireAuthorization`，泄露内部依赖 | CWE-200 |
| **HSTS 短期** | Program.cs | `UseHsts()` MaxAge < 1 年 | CWE-319 |

**Step 3: 反序列化全局配置检查**
```bash
# Json.NET 全局 TypeNameHandling
grep -rn 'JsonConvert\.DefaultSettings\|TypeNameHandling' TARGET_DIR --include='*.cs'
# 任何非 None 值都是 CRITICAL
# System.Text.Json 全局多态配置
grep -rn 'JsonSerializerOptions\|TypeInfoResolver' TARGET_DIR --include='*.cs'
# YamlDotNet 默认配置
grep -rn 'DeserializerBuilder\|new Deserializer\(' TARGET_DIR --include='*.cs'
```

**Step 4: 中间件管道顺序检查**

中间件顺序错误等同未启用，必须验证：
```bash
# 在 Program.cs / Startup.Configure 中按顺序提取所有 app.UseXxx 调用
grep -n 'app\.Use[A-Z]' Program.cs
```
**强制顺序规则：**
- `UseHttpsRedirection` 必须在 `UseStaticFiles` 之前
- `UseAuthentication` 必须在 `UseAuthorization` 之前
- 自定义安全中间件必须在 `UseEndpoints`/`MapControllers` 之前
- `UseCors` 必须在 `UseAuthentication` 之前（特定场景）
- `UseExceptionHandler` 必须在管道最前

**Step 5: NuGet 依赖配置检查**
```bash
# 危险包识别
grep -rn 'BinaryFormatter\|System.Runtime.Serialization.Formatters' *.csproj
# 已知存在 RCE 历史的包
grep -rn 'Newtonsoft.Json.*Version="(9|10|11|12)\.' *.csproj  # 老版默认 TypeNameHandling 不安全
```

**Step 6**: 若项目使用上述库（即使无显式配置类），相关检查仍为强制项 — 库可能使用不安全默认值。

### Phase 3.9: Defense Verification (加固验证)

**目的**：判断每个潜在漏洞是否真的可利用，识别"已加固但仍可绕过"和"看似漏洞实际已加固"两类情况，大幅降低误报和漏报。

**触发条件**：所有 Phase 3 / Phase 3.6 / Phase 3.8 报告的潜在漏洞，按严重性优先级处理。

#### 6 层加固验证流程

每个潜在漏洞**必须**通过以下 6 层验证，任一层"加固有效"则降级，全部缺失则保留原评级。

##### 第 1 层：入口层加固（Global Filter / Middleware）

**.NET 检查项：**
```bash
# 全局 ActionFilter
grep -rn 'IActionFilter\|IAsyncActionFilter\|services\.AddControllers.*Filters\.Add' TARGET_DIR --include='*.cs'
# 中间件
grep -rn 'IMiddleware\|app\.Use(' TARGET_DIR --include='*.cs'
# 授权过滤器
grep -rn 'IAuthorizationFilter\|IAsyncAuthorizationFilter' TARGET_DIR --include='*.cs'
```

**Java 检查项：**
```bash
grep -rn 'implements Filter\|HandlerInterceptor\|OncePerRequestFilter\|@WebFilter' TARGET_DIR --include='*.java'
```

**判定规则：**
- 全局过滤器对该漏洞类型有 sanitizer/拦截 → `MITIGATED_GLOBAL`
- 黑名单方式（关键字过滤）→ `PARTIALLY_MITIGATED`（标注绕过点）
- 白名单 + 严格类型校验 → `MITIGATED_STRONG`

##### 第 2 层：参数校验注解加固

**.NET 检查项（Controller/DTO 注解）：**
```csharp
[RegularExpression(@"^\d+$")]      // 强加固
[Range(1, 100)]                     // 强加固
[StringLength(50)]                  // 弱加固（仅长度）
[DataType(DataType.EmailAddress)]   // 中加固
[FromRoute] int id                  // 类型强校验
[FromQuery] Guid id                 // 类型强校验
```
还需检查：`if (!ModelState.IsValid) return BadRequest();` 是否存在。

**Java 检查项：**
```java
@Pattern(regexp="^\\d+$")  @NotNull  @Size  @Min  @Max  @Email
@Valid + @NotBlank  // 必须配 @Valid 才生效
```

**判定规则：**
- 危险参数被 `[RegularExpression]` / `@Pattern` 严格约束 → `MITIGATED_STRONG`
- 仅 `[StringLength]` / `@Size` → `WEAK_MITIGATION`（限长度不限内容）
- 无任何注解 → `NO_MITIGATION`

##### 第 3 层：白名单/黑名单校验

**搜索模式：**
```bash
# 白名单
grep -B2 -A5 'HashSet\|AllowedValues\|.Contains(\|switch.*case\|enum' [danger_file]
# 黑名单
grep -B2 -A5 'BlackList\|Forbidden\|Regex.IsMatch\|.Replace(' [danger_file]
```

**判定规则：**
- `HashSet<string>.Contains()` 白名单校验 → `MITIGATED_STRONG`
- 黑名单关键字过滤 → `PARTIALLY_MITIGATED`（标注绕过：编码/注释/大小写/宽字节/Unicode 同形）
- switch + 默认 BadRequest → `MITIGATED_STRONG`

##### 第 4 层：净化函数（Sanitizer）调用

**.NET Sanitizer 清单：**
- HTML: `HttpUtility.HtmlEncode`, `HtmlEncoder.Default.Encode`, `AntiXssEncoder`
- URL: `Uri.EscapeDataString`, `HttpUtility.UrlEncode`
- SQL: `SqlParameter`, `SqlCommand.Parameters.Add`, `@param + DbCommand`
- LDAP: 自定义 `LdapEncoder.FilterEncode`（通常缺失）
- Path: `Path.GetFileName`, `Path.GetFullPath` + 前缀比对

**Java Sanitizer 清单：**
- HTML: `OWASP ESAPI`, `Jsoup.clean`, `HtmlUtils.htmlEscape`
- URL: `URLEncoder.encode`
- SQL: `PreparedStatement`, MyBatis `#{}`
- LDAP: `LdapEncoder.filterEncode`
- Path: `org.apache.commons.io.FilenameUtils.getName`

**判定规则：**
- 危险数据流上调用了**对应类型** sanitizer → `MITIGATED_STRONG`
- 调用了**不匹配类型**的 sanitizer（如 SQL 注入只做 HtmlEncode）→ `NOT_MITIGATED`（错误加固，仍是漏洞）

##### 第 5 层：框架默认安全机制

**.NET 默认安全行为清单：**
- `System.Text.Json` 默认 `MaxDepth=64`、不支持多态 → JSON 反序列化默认安全
- EF Core LINQ 自动参数化 → SQL 注入安全（除 `FromSqlRaw`/`ExecuteSqlRaw`）
- ASP.NET Core MVC `[ValidateAntiForgeryToken]` Razor Pages 默认开启
- `HttpClient` 默认验证证书 → TLS 安全（但可能 SSRF）
- Razor `@Model.Property` 默认 HtmlEncode → XSS 默认安全（除 `@Html.Raw`）

**Java 默认安全行为清单：**
- Spring Boot 2.3+ Jackson 默认 `FAIL_ON_UNKNOWN_PROPERTIES=true`
- Spring Security 6.0+ CSRF 默认开启
- Thymeleaf `[[${var}]]` 默认 HTML 转义

**判定规则：**
- 使用框架默认安全 API + 未禁用 → `MITIGATED_STRONG`
- 使用了显式 unsafe API（`@Html.Raw`、`FromSqlRaw`、`BinaryFormatter`）→ `NO_MITIGATION`

##### 第 6 层：使用场景上下文分析

**关键原则：危险代码 ≠ 漏洞，必须分析使用场景。**

| 危险代码 | 上下文 1（漏洞） | 上下文 2（非漏洞） |
|---------|---------------|----------------|
| MD5 | 密码哈希 → CRITICAL | 文件 ETag 去重 → 无问题 |
| eval() | 处理用户输入 → CRITICAL | 处理服务端常量 → 代码异味 |
| BinaryFormatter | 反序列化 HTTP 输入 → CRITICAL | 反序列化本地配置文件 → 低风险 |
| Process.Start | 拼接用户输入 → RCE | 启动固定路径程序 → 无问题 |
| HttpClient.Get(url) | url 来自请求参数 → SSRF | url 是配置常量 → 无问题 |

**强制：每个发现必须明确标注使用场景，禁止仅凭函数名定级。**

#### 加固验证输出格式

每个发现必须包含此区块：

```
**加固验证（Defense Verification）**:
- 第1层 入口过滤器: ✅ XssMiddleware 处理所有响应 (MITIGATED_STRONG)
- 第2层 参数注解: ⚠️ 仅 [StringLength(50)] (WEAK_MITIGATION)
- 第3层 白/黑名单: ❌ 无 (NO_MITIGATION)
- 第4层 Sanitizer: ❌ 直接拼接 (NO_MITIGATION)
- 第5层 框架默认: ❌ 使用 @Html.Raw 显式禁用编码 (NO_MITIGATION)
- 第6层 使用场景: 用户搜索关键字直接渲染到搜索结果页 (REAL_VULN)

**最终评级**:
- 原始评级: Critical
- 加固后评级: High (有出口编码可能阻断部分 payload)
- 实际可利用性: HIGH (`<img src=x onerror=alert(1)>` 可绕过)
- 状态: REAL_VULNERABILITY (需修复)
```

#### 加固后状态分类

| 状态 | 含义 | 报告处置 |
|------|------|--------|
| `REAL_VULNERABILITY` | 加固缺失或可绕过，确认可利用 | 主报告，原评级 |
| `PARTIALLY_MITIGATED` | 加固存在但有绕过空间 | 主报告，附绕过 PoC，降一级 |
| `MITIGATED_STRONG` | 多层加固，无明显绕过 | 移至"已加固代码异味"附录，不计入漏洞数 |
| `CONTEXT_NOT_VULNERABLE` | 危险代码但场景不构成漏洞 | 不计入报告，记入 false-positives.md |
| `NEEDS_VERIFY` | 加固层难以判定 | 标记，强制进入 Phase 3.10 多 Agent 验证 |

### Phase 3.9.4: Web Entry Path Tracing (Web 入口路径完整追踪)

**目的**：在做污点追踪之前，必须先建立**完整的 HTTP 请求路由映射**——从 URL 一路追到具体的处理代码。任何"漏掉入口"会让后续的污点追踪缺少 Source。

**触发条件**：所有 Web 应用项目，**强制执行**，先于 Phase 3.9.5 污点追踪。

#### Web 入口的 7 类路径（必须穷举）

##### 1. 框架级路由

| 框架 | 入口配置 | 必须读取 |
|------|---------|--------|
| **ASP.NET WebForms** | `Web.config` `<httpHandlers>`, `<system.webServer><handlers>`, `<defaultDocument>` | 所有 `.aspx`, `.ashx`, `.asmx` 文件 + 配置 path 模式 |
| **ASP.NET MVC** | `RouteConfig.cs`, `Global.asax.cs`, `[Route(...)]` | 所有 `Controller.cs` + `MapRoute` 调用 |
| **ASP.NET Core** | `Program.cs`/`Startup.cs` 中的 `MapControllers`, `MapGet`, `MapPost`, `MapHub`, `MapEndpoints` | + 所有 `[HttpGet/Post/...]`、Minimal API |
| **Spring Boot** | `@Controller`, `@RestController`, `@RequestMapping`, `@GetMapping` | + WebFlux `RouterFunction` |
| **Spring Cloud Gateway** | `application.yml routes:` | + `RouteLocator` Bean |
| **Express.js** | `app.get/post/use(path, handler)` | + Router 实例 |
| **Django** | `urls.py` `urlpatterns` | + `re_path`, `path`, `include` |
| **Flask** | `@app.route`, `@blueprint.route` | + `add_url_rule` |
| **FastAPI** | `@app.get/post`, `APIRouter` | |
| **Go** | `http.HandleFunc`, `mux.Handle`, `gin.GET` | |
| **PHP/Laravel** | `routes/web.php`, `routes/api.php`, `Route::get` | + `.htaccess` rewrite |
| **Ruby/Rails** | `config/routes.rb`, `resources :xxx` | |

##### 2. 服务器/容器级路由

| 类型 | 必须检查 |
|------|--------|
| **IIS** | `Web.config <handlers>`, `<modules>`, `applicationHost.config`（如可访问），URL Rewrite 规则 |
| **Apache** | `.htaccess`, `httpd.conf`, `<VirtualHost>`, `RewriteRule`, `<Directory>`, `<Location>` |
| **Nginx** | `nginx.conf`, `conf.d/*.conf`, `location` 块, `proxy_pass`, `rewrite` |
| **Tomcat** | `web.xml` `<servlet-mapping>`, `<filter-mapping>`, `Context.xml` |
| **Kestrel/Caddy** | 配置文件 + middleware 顺序 |

##### 3. HTTP Module / Middleware 拦截链

**必须按管道顺序列出所有中间件**，因为每一层都可能：
- 改写 URL（重写）
- 改写参数（添加/删除 header）
- 强制鉴权或绕过鉴权
- 拦截/阻断请求

| 框架 | 检查模式 |
|------|--------|
| **ASP.NET WebForms** | `Global.asax` 的 `Application_BeginRequest/AuthenticateRequest`，`<httpModules>` 配置 |
| **ASP.NET Core** | `app.UseXxx()` 顺序（必须按序列出） |
| **Spring** | `@Order` 注解的 `Filter`/`HandlerInterceptor` |
| **Express** | `app.use()` 顺序 |
| **Django** | `settings.py MIDDLEWARE` 列表 |

##### 4. 静态资源 + 默认文档

```bash
# 必须确认这些"看似无害"的入口
- defaultDocument 配置（IIS）
- DirectoryIndex (Apache)
- index 指令 (Nginx)
- 静态资源路径是否被 require 鉴权
- 上传目录是否在 web 根 → 直接访问下载
```

##### 5. 反向代理 / 网关路由

```bash
# 真实 URL 可能与代码内路由不同
- Nginx proxy_pass /api/ → http://backend/  (前缀剥离)
- API Gateway 路由表（Kong, Spring Cloud Gateway）
- AWS ALB / CloudFront 行为
- Service Mesh (Istio VirtualService)
```

##### 6. 隐藏入口（容易遗漏）

| 类型 | 模式 |
|------|------|
| **错误处理页面** | ASP.NET `customErrors defaultRedirect`, Spring `@ControllerAdvice`, Express `app.use(errorHandler)` |
| **回调/Webhook 端点** | OAuth callback, 支付回调, GitHub webhook |
| **健康检查** | `/health`, `/actuator/health`, `MapHealthChecks` |
| **管理端点** | `/actuator/*`, `/swagger`, `/metrics`, `/admin` |
| **WebSocket** | `MapHub`, `@ServerEndpoint`, `app.ws()` |
| **gRPC** | `service.AddGrpcService`, proto 定义 |
| **GraphQL** | 单一 `/graphql` 入口下所有 query/mutation |
| **SignalR** | `app.MapHub<T>("/hub")` |
| **MVC 隐式路由** | `{controller}/{action}/{id?}` 默认路由 |
| **WebForms PostBack** | `__VIEWSTATE`、`__EVENTTARGET`（任何 .aspx 都可能被 POST） |
| **AJAX/REST 端点** | `.ashx`, `.asmx`, `Web API` |

##### 7. 非 HTTP 入口（仍需追踪）

| 入口类型 | 模式 |
|---------|------|
| **定时任务** | Quartz, Hangfire, `[Scheduled]` 注解, cron |
| **MQ 消费者** | `@KafkaListener`, `@RabbitListener`, `IConsumer<T>` |
| **CLI 命令** | `Program.Main(args)`, `argparse` |
| **文件监听** | `FileSystemWatcher`, `inotify` |

#### 强制执行的 6 步流程

##### Step 1：识别 Web 框架与服务器
```bash
# .NET WebForms 标识
ls Web.config Global.asax *.aspx *.ashx 2>/dev/null
# .NET Core 标识
ls Program.cs Startup.cs *.csproj 2>/dev/null && grep 'WebApplication\|IServiceCollection' Program.cs
# Java Spring 标识
ls pom.xml build.gradle 2>/dev/null && grep '@SpringBootApplication\|@Controller'
# Node.js
ls package.json 2>/dev/null && grep -E '"express"|"koa"|"fastify"|"hapi"'
```

##### Step 2：建立 URL → Handler 完整映射表

输出格式（强制）：
```
| URL 模式 | HTTP 方法 | Handler 类型 | Handler 位置 | 配置来源 | 认证要求 |
|---------|---------|-----------|------------|--------|--------|
| /Login.aspx | GET,POST | WebForms Page | Login.aspx:5 (Page_Load) | Web.config:113 <location> | 匿名 |
| *.rsb | GET,PUT,POST,DELETE,MERGE,HEAD,OPTIONS | RSSBus.RSBScript | bin/RSSBus.dll | Web.config:31 httpHandlers | 默认 deny |
| pub/* | * | RSSBus.RSBScript | bin/RSSBus.dll | Web.config:120 <location path="pub"> | 匿名 |
| / (default) | GET | RSSBus.RSBTemplate (default.rst) | bin/RSSBus.dll | Web.config:62-65 defaultDocument | 默认 deny |
```

##### Step 3：列出 HTTP Module / Middleware 顺序

```
请求流（按执行顺序）：
1. IIS [URL 路由匹配 handlers]
2. UrlAuthorizationModule (Web.config <authorization>)
3. FormsAuthenticationModule（已 remove FileAuthorization）
4. Global.asax Application_BeginRequest（如有）
5. RSSBus.RSBScript / RSBTemplate Handler ProcessRequest
6. .aspx Page_Load
```

##### Step 4：标记每个入口的"暴露面"

每条入口必须给出：
- **协议**: HTTP / HTTPS / WS / WSS
- **公网/内网**: 取决于 IIS site binding（注意 `httpRedirect`、`requireSSL`）
- **认证级别**: 匿名 / 任意登录用户 / 特定角色
- **请求体最大大小**: `maxRequestLength`、`MaxRequestBodySize`
- **超时**: `executionTimeout`、`KeepAliveTimeout`
- **是否启用 ValidateRequest**: 控制 ASP.NET 默认 XSS 防御
- **是否绕过文件授权**: `<remove name="FileAuthorization"/>` 等

##### Step 5：处理"配置层鉴权" vs "代码层鉴权"分歧

很多漏洞来自这两层不一致：
- Web.config `<allow users="*"/>` 但 Page_Load 内部又做了角色检查 → 鉴权位置必须查代码
- Spring SecurityConfig `permitAll()` 但 Controller 内有 `if (user.role == admin)` → 看代码
- 反之：配置 `[Authorize]` 但具体 action 标了 `[AllowAnonymous]` → action 优先

##### Step 6：识别"未在源码中的入口"

商业产品（如本案例 CData Arc）大量逻辑在编译 DLL，必须：
- 列出所有自定义 IHttpHandler 类型 → 反编译 DLL 找 ProcessRequest
- 列出所有 IHttpModule 实现 → 反编译 DLL
- 标 `BROKEN_TRACE_AT_DLL`，触发 Phase 1.5 反编译流程

#### 输出：Web 入口完整追踪报告

每个项目必须有此章节：

```
## Web 入口路径完整追踪

### 1. 框架识别
- ASP.NET WebForms (.NET Framework 4.x)
- IIS 7+ Integrated Pipeline
- 自定义 HTTP Handler: RSSBus.dll

### 2. URL → Handler 映射表
[完整表格，每条 URL 一行]

### 3. 中间件 / Module 执行链
[按顺序列出]

### 4. 每条入口的暴露面
[逐条标注 协议/认证/限制]

### 5. 配置层 vs 代码层鉴权差异
[如有]

### 6. BROKEN_TRACE 入口（编译 DLL 中）
- *.rsb → RSSBus.RSBScript.ProcessRequest in RSSBus.dll [需反编译]
- *.rsc → RSSBus.RSBDataCollection.ProcessRequest in RSSBus.dll [需反编译]
- *.rsd → RSSBus.RSBData.ProcessRequest in RSSBus.dll [需反编译]
```

#### 强制规则

1. **此 Phase 在 Phase 3.9.5 污点追踪之前执行**，否则污点追踪缺 Source
2. **每条 URL 模式必须确定 Handler**，不能写"未知"
3. **`<remove>` 模块必须特别标注**（移除安全模块通常是高危信号）
4. **看似无关的 .aspx 也必须列入**（任何 ASP.NET 页面都可能被 POST）
5. **遇到反向代理，必须索取代理配置**或标注 `EXTERNAL_PROXY_NEEDED`
6. **handler 在编译 DLL 中** → 触发 Phase 1.5 反编译，不允许跳过

### Phase 3.9.5: Taint Tracking (污点追踪 - 漏洞真实性确认)

**目的**：每个潜在漏洞必须通过完整的 **Source → Sanitizer → Sink** 污点追踪，证明从 HTTP 入口到危险操作之间存在**真实可达的数据流**。无法证明可达的发现一律降级。

**触发条件**：所有 Phase 3 报告的发现，**强制执行**，不可跳过。

#### 污点追踪三要素

##### 1. Source（污点源）：用户可控输入

**HTTP 入口（Web 应用）**
- .NET: `Request.Form[]`, `Request.QueryString[]`, `Request.Headers[]`, `Request.Cookies[]`, `Request.Params[]`, `Request[]`, `Request.Url`, `Request.RawUrl`, `Request.UrlReferrer`, `Request.Files[]`, `IFormFile`, `[FromQuery]`, `[FromBody]`, `[FromRoute]`, `[FromHeader]`, `[FromForm]`
- Java: `request.getParameter()`, `request.getHeader()`, `@RequestParam`, `@RequestBody`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `MultipartFile`
- Python: `request.args`, `request.form`, `request.json`, `request.headers`, `request.files`, `request.GET`, `request.POST`
- Node.js: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `req.files`
- PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER['HTTP_*']`, `$_FILES`, `php://input`
- Go: `r.URL.Query()`, `r.FormValue()`, `r.PostFormValue()`, `r.Header.Get()`, `r.MultipartForm`

**间接 Source（二级污点源）**
- 数据库读取（数据本身可能被污染 — 二级注入 / 存储型 XSS）
- 文件读取（用户上传的文件）
- 消息队列消息体
- 第三方 API 响应（攻击者可控的外部服务）
- 环境变量（在 SaaS 多租户中可能可控）
- Session/Cache（若可被其他端点污染）

##### 2. Sanitizer（净化函数）：阻断污点传播

每种 Sink 对应特定 Sanitizer，**类型不匹配的 Sanitizer 视为无效**。

| Sink 类型 | 有效 Sanitizer (.NET) | 有效 Sanitizer (Java) |
|----------|------------------|------------------|
| SQL | `SqlParameter`, `cmd.Parameters.AddWithValue`, `FromSqlInterpolated` | `PreparedStatement`, MyBatis `#{}` |
| HTML/XSS | `HttpUtility.HtmlEncode`, `HtmlEncoder.Default.Encode`, `AntiXssEncoder` | `HtmlUtils.htmlEscape`, OWASP ESAPI, Jsoup.clean |
| URL | `Uri.EscapeDataString`, `HttpUtility.UrlEncode` | `URLEncoder.encode` |
| Path | `Path.GetFileName` + `Path.GetFullPath` 前缀比对 | `FilenameUtils.getName` |
| LDAP | 自定义 LDAP encoder | `LdapEncoder.filterEncode` |
| OS Command | 参数数组传递（不拼字符串）+ 白名单 | `ProcessBuilder` 数组 + 白名单 |
| XML/XXE | `XmlReader` + `DtdProcessing.Prohibit` | `setFeature("disallow-doctype-decl", true)` |
| JSON 反序列化 | `TypeNameHandling=None`, 限定 `KnownTypes` | Jackson 关闭 `enableDefaultTyping` |
| 整数边界 | `int.TryParse`, `Range` 校验 | `Integer.parseInt` + `if (x>0 && x<MAX)` |
| 路径白名单 | `HashSet<string>.Contains()` | Set + contains |
| 业务类型 | `Enum.TryParse` strict, GUID parse | Enum.valueOf 严格匹配 |

**判定规则**：
- 数据流上有**类型匹配** Sanitizer → 污点已清洗 → `MITIGATED`
- 数据流上有**类型不匹配** Sanitizer（如 SQL 注入只做 HtmlEncode）→ 视为无效 → `STILL_TAINTED`
- 数据流分支：**只要存在一条未净化路径**就视为有漏洞
- Sanitizer 在条件分支中（`if (x) sanitize(); else dangerous();`）→ 必须验证两条路径

##### 3. Sink（危险接收点）：执行污点的危险操作

| Sink 类型 | .NET 模式 | Java 模式 |
|----------|---------|---------|
| SQL Sink | `SqlCommand.ExecuteXxx`, `FromSqlRaw`, `ExecuteSqlRaw` | `Statement.execute*`, MyBatis `${}` |
| Command Sink | `Process.Start`, `PowerShell.AddScript` | `Runtime.exec`, `ProcessBuilder` |
| Code Eval Sink | `CSharpCodeProvider`, `Roslyn.Compile` | `ScriptEngine.eval`, `Class.forName` + `Method.invoke` |
| Path Sink | `File.Open`, `File.ReadAllText`, `Path.Combine` (写) | `new File()`, `FileInputStream`, `FileWriter` |
| Reflection Sink | `Type.GetType(s).InvokeMember` | `Class.forName(s).getMethod()` |
| Deserialize Sink | `BinaryFormatter.Deserialize`, `JsonConvert.DeserializeObject(..., AllSettings)` | `ObjectInputStream.readObject` |
| Render Sink | `@Html.Raw`, `Response.Write` 含 HTML | `out.print`, `${var}` (无转义) |
| Redirect Sink | `Response.Redirect(url)` | `response.sendRedirect(url)` |
| HTTP Out Sink | `HttpClient.GetAsync(url)` | `URL(url).openConnection()` |
| Header Sink | `Response.Headers.Add(k, v)` | `response.setHeader(k, v)` |
| LDAP Sink | `DirectorySearcher.Filter` | `DirContext.search(filter)` |
| XPath Sink | `XPathNavigator.Compile`, `SelectNodes` | `XPath.compile`, `Document.evaluate` |
| Crypto Sink | `MachineKey.Encode`, `RNGCryptoServiceProvider` | `Cipher.getInstance` |

#### 污点追踪执行流程（每个发现强制 5 步）

##### Step 1: 锁定 Sink
找到具体危险调用所在的 `file:line`，准确到参数级别。

##### Step 2: 反向追溯参数来源
从 Sink 参数倒推：
```
Sink(param) ← 函数 A 的局部变量 ← 函数 A 的入参 ← 调用 A 的函数 B ← ... ← Controller 的 [FromBody] dto
```
要求：
- 列出**完整调用栈**（每一层 file:line）
- 列出每一层的变量重命名（`name` → `fullName` → `searchTerm` → `userInput`）
- 跨文件、跨类、跨方法必须显式标注

##### Step 3: 标记数据流上的所有变换

| 变换类型 | 是否清洗污点 | 备注 |
|---------|----------|------|
| 字符串拼接 (`a + b`, `$"{a}"`) | ❌ 不清洗 | 污点继续传播 |
| `string.Replace(...)` | ⚠️ 视情况 | 需评估是否覆盖所有 payload |
| `Trim`, `ToUpper`, `ToLower` | ❌ 不清洗 | 污点继续传播 |
| `Substring` | ⚠️ 视情况 | 截断可能保留危险片段 |
| `int.Parse`, `Guid.Parse` | ✅ 类型清洗 | 字符串污点变成数值/GUID |
| `Enum.Parse` (strict) | ✅ 类型清洗 | 限制为枚举值集合 |
| 类型匹配 Sanitizer | ✅ 已清洗 | 污点终止 |
| 序列化/反序列化 | ⚠️ 视情况 | JSON 反序列化不清洗，仍可注入 |
| 数据库写入 → 读取 | ⚠️ 二次污点 | 跨请求污点持久化（存储型 XSS） |

##### Step 4: 评估可达性条件

不是每个 Sink 都能从外部触发，必须确认：
- HTTP 入口的认证要求（前台/后台/管理员）— 引用 Phase 1 Endpoint Authentication Matrix
- 触发该 Sink 是否需要特定输入条件
- 是否需要前置漏洞（如先 SSRF 再 RCE）
- 业务流程是否实际开放该路径

##### Step 5: 输出污点追踪结论

```
**污点追踪 (Taint Trace)** [VULN-XXX]:

Source: HTTP 入口
  - 端点: POST /api/search
  - 参数: dto.keyword (来源 [FromBody] SearchDto)
  - 文件: SearchController.cs:42
  - 认证要求: 前台(匿名)

数据流路径:
  [1] SearchController.cs:42 → dto.keyword (string, tainted)
  [2] SearchController.cs:48 → keyword = dto.keyword.Trim()  (污点保留)
  [3] SearchController.cs:50 → SearchService.SearchAsync(keyword)
  [4] SearchService.cs:22 → BuildSql(keyword)
  [5] SearchService.cs:35 → sql = $"SELECT * FROM users WHERE name = '{keyword}'"  (拼接，污点保留)
  [6] SearchService.cs:38 → _db.Database.ExecuteSqlRaw(sql)  ← Sink

Sanitizer 分析:
  - [2] Trim() — 不清洗 SQL 注入污点
  - [3]-[5] 无任何 Sanitizer 调用
  - 结论: STILL_TAINTED

可达性:
  - HTTP 入口: 前台无需认证 (Web.config: <allow users="*" path="search">)
  - 触发条件: 任意 POST 请求带 keyword 字段
  - 业务路径: 主搜索栏直接调用此接口

PoC:
  curl -X POST 'https://target/api/search' \
    -H 'Content-Type: application/json' \
    -d '{"keyword":"x'\'' OR 1=1--"}'

最终判定: REAL_VULNERABILITY ✅
置信度: 95%
- 完整污点路径已确认
- 无 Sanitizer 阻断
- 公开可达
- PoC 可验证
```

#### 污点追踪状态分类

| 状态 | 含义 | 处置 |
|------|------|------|
| `REAL_VULNERABILITY` | 完整污点路径 + 无清洗 + 可达 | 主报告 |
| `MITIGATED_BY_SANITIZER` | 路径上有有效 Sanitizer | 不入主报告，记加固模式 |
| `MITIGATED_BY_TYPE_CONVERSION` | 类型转换清洗（int/GUID/enum） | 不入主报告 |
| `UNREACHABLE` | 无 HTTP 入口 / 死代码 | 移至代码质量章节 |
| `CONDITIONAL_REACHABLE` | 需要特定前置条件 | 主报告，标注前置条件 |
| `INDIRECT_TAINT` | 间接污点（DB 二次注入、文件污点） | 主报告，单独标记 |
| `BROKEN_TRACE` | 调用链中断（如调用编译 DLL 内部方法） | 进入 Phase 1.5 反编译，或标 NEEDS_DECOMPILE |

#### 污点追踪强制规则

1. **每个 Critical/High 发现必须有完整污点追踪**，缺失则不允许进入主报告
2. **跨文件追溯必须显式 Read 每个文件**，不能凭函数名推测
3. **污点路径必须画出完整链路**（5 步以上的链路用列表呈现）
4. **遇到反编译代码或外部库**，必须明确标注 `BROKEN_TRACE`，不能跳过
5. **多入口情况**（一个 Sink 可被多个 Controller 触达）每条入口必须独立追溯
6. **存储型污点**（DB → 读 → Sink）必须证明写入端可被污染

### Phase 3.10: Multi-Agent Verification (多 Agent 真实性验证)

**目的**：对所有 Critical/High 以及 Phase 3.9 标记 `NEEDS_VERIFY` 的发现，启动多个独立 Agent 并行验证，通过**多视角交叉验证**确认漏洞真实存在，将单 Agent 误判的概率降到最低。

**触发条件**：
- 所有严重性 Critical 或 High 的发现
- 加固验证标记 `NEEDS_VERIFY` 的发现
- 涉及 Phase 3.7 组合攻击链的发现
- 高混淆代码或反编译代码的发现

#### 多 Agent 验证架构

为每个待验证漏洞，**并行启动 3 个独立 Agent**，三 Agent 互不知情、从不同视角分析。使用 Agent 工具并行调用，subagent_type 选择 general-purpose。

##### Agent A：攻击者视角（Red Team Agent）

**任务提示词模板：**
```
你是渗透测试专家。给定以下漏洞信息：
- HTTP 入口: {endpoint}
- 漏洞类型: {vuln_type}
- 用户可控参数: {param}
- 调用链: {call_chain}
- 文件位置: {file_path}:{line_start}-{line_end}

请完成（不要假设无加固）：
1. 阅读目标代码及调用链上的所有文件
2. **强制执行污点追踪**（Phase 3.9.5）：从 HTTP Source 到 Sink 完整列出每一步变量传播
3. 列出**所有**可能的中间过滤、校验、净化层（含中间件/过滤器/注解/白名单/Sanitizer）
4. 针对每一层加固，构造尝试绕过的 payload（编码绕过、大小写绕过、Unicode 同形、注释绕过等）
5. 给出最小可利用的 PoC（curl 命令或 Python 脚本）
6. 明确输出: EXPLOITABLE / NOT_EXPLOITABLE / CONDITIONAL + 理由
7. **必须输出污点路径清单**，每一步引用 file:line
```

##### Agent B：防御者视角（Blue Team Agent）

**任务提示词模板：**
```
你是 .NET/Java 安全架构师。给定以下"潜在漏洞"信息：
- 文件: {file_path}
- 行号: {line_start}-{line_end}
- 报告类型: {vuln_type}

请完成（不要预设这是漏洞，请尽量证明它已被加固）：
1. 读取目标代码及调用链上的所有文件
2. 列出该代码受到的所有保护机制（中间件/过滤器/注解/Sanitizer/框架默认）
3. 检查是否使用了框架的默认安全机制
4. 分析使用场景，判定危险代码是否在敏感上下文
5. 明确输出: REAL_VULN / MITIGATED / FALSE_POSITIVE + 加固点引用 (file:line)
```

##### Agent C：独立审计视角（Cross-Check Agent）

**任务提示词模板：**
```
你是独立第三方代码审计专家。请勿假设之前任何分析正确。
- 文件: {file_path}
- 行号: {line_start}-{line_end}
- 报告类型: {vuln_type}

请完成：
1. 直接读取目标代码及完整上下文（前后 50 行 + 同文件 imports + 调用方/被调方）
2. **不参考任何先前分析结果**
3. 独立判定该代码是否构成漏洞
4. 列出判定依据（必须引用具体代码行）
5. 评估可利用性的**客观证据**（不要凭直觉，需具体 payload 或加固代码）
6. 最终输出: CONFIRMED_VULN / FALSE_POSITIVE / INSUFFICIENT_INFO
```

#### 三方裁决规则

收集 3 个 Agent 的结论，按下表裁决：

| Agent A | Agent B | Agent C | 最终判定 |
|---------|---------|---------|--------|
| EXPLOITABLE | REAL_VULN | CONFIRMED_VULN | ✅ **CONFIRMED**（高置信度，直接进主报告） |
| EXPLOITABLE | MITIGATED | CONFIRMED_VULN | ⚠️ **DISPUTED**（启动 Agent D 仲裁） |
| EXPLOITABLE | MITIGATED | FALSE_POSITIVE | ⚠️ **DISPUTED**（启动 Agent D 仲裁） |
| NOT_EXPLOITABLE | MITIGATED | FALSE_POSITIVE | ❌ **FALSE_POSITIVE**（自动剔除并写入 false-positives.md） |
| CONDITIONAL | REAL_VULN | CONFIRMED_VULN | ⚠️ **CONDITIONAL**（标注前提条件后入主报告） |
| 任何 | INSUFFICIENT_INFO | INSUFFICIENT_INFO | 🔍 **NEEDS_HUMAN_REVIEW** |
| 2 票 CONFIRM | 1 票 NEG | - | ⚠️ **DISPUTED** → Agent D |
| 2 票 NEG | 1 票 CONFIRM | - | 默认采纳多数，但记录少数意见 |

#### Agent D：仲裁 Agent（仅在 DISPUTED 时启动）

**任务提示词模板：**
```
你是首席安全研究员。三个 Agent 对此漏洞判定不一致：
- Agent A 攻击者: {a_conclusion} + 完整理由
- Agent B 防御者: {b_conclusion} + 完整理由
- Agent C 独立: {c_conclusion} + 完整理由

请：
1. 阅读完整代码上下文
2. 评估三方理由的证据强度（具体代码行 vs 推测）
3. 实际尝试 Agent A 的 PoC，分析为何 Agent B 认为已加固
4. 给出最终裁决 + 理由 + 置信度（0-100%）
5. 若置信度 < 80%，建议进入 Phase 4 实际 PoC 验证
6. 输出: FINAL_CONFIRMED / FINAL_FALSE_POSITIVE / NEEDS_RUNTIME_VERIFY
```

#### 多 Agent 验证输出格式

```
**多 Agent 验证结果** (VULN-001):

[Agent A - 攻击者视角]
结论: EXPLOITABLE
PoC: curl -X POST 'http://target/api/search?q=%27%20OR%201=1--'
绕过分析: WAF 黑名单未覆盖大小写 SeLeCt

[Agent B - 防御者视角]
结论: MITIGATED
依据: SqlInjectFilter.cs:45 拦截 union/select/-- 关键字

[Agent C - 独立审计视角]
结论: CONFIRMED_VULN
独立判定: WAF 用 Regex.IsMatch 但未启用 IgnoreCase，可被大小写绕过

[Agent D - 仲裁]
最终裁决: FINAL_CONFIRMED
置信度: 95%
理由: Agent A 与 C 独立得出可绕过结论；Agent B 漏判加固缺陷（缺少 IgnoreCase 标志）
```

#### 验证结果对报告的影响

- `CONFIRMED` → 主报告，标注"已通过多 Agent 交叉验证"
- `DISPUTED` → 主报告，附三方意见 + 必须执行 Phase 4 PoC
- `CONDITIONAL` → 主报告，明确前提条件
- `FALSE_POSITIVE` → 不进入主报告，自动追加到 `references/false-positives.md`，附排除理由
- `NEEDS_HUMAN_REVIEW` → 单独"待人工复核"章节

#### Token 预算控制

为避免 Agent 调用爆炸：
- 仅对 Critical/High 启动 Phase 3.10（Medium/Low 跳过）
- 单个项目最多启动 30 组三 Agent 验证
- 若超出预算，按"严重性 × 加固验证置信度"排序优先验证
- 每个 Agent 最大上下文 50K tokens
- Agent D 仲裁仅在 DISPUTED 时启动，最多 10 次/项目

#### 自我演化反馈

每次 Phase 3.10 验证完成后：
- `CONFIRMED` 模式 → 写入 `references/confirmed-patterns.md`，加权重
- `FALSE_POSITIVE` 模式 → 写入 `references/false-positives.md`，附三方意见摘要
- `DISPUTED` 模式 → 写入新文件 `references/disputed-cases.md` 供后续学习

### Phase 4: PoC Verification (Optional)

For HIGH and CRITICAL findings, optionally generate and execute verification scripts:
- **L1 (default)**: Static verification — validate file paths exist, code snippets match actual files, cross-reference with Semgrep results
- **L2 (if test environment available)**: Execute curl/HTTP requests against the target to confirm exploitability
- **L3 (if Docker available)**: Run PoC scripts in isolated Docker containers (network=none, memory=512m)

Mark each finding as: CONFIRMED / LIKELY / UNCONFIRMED

### Phase 6: Feedback & Self-Evolution

After delivering the report, follow `scripts/post-audit-feedback.md`:
1. **Collect feedback**: Ask user which findings are confirmed vs false positives
2. **Update patterns**: Confirmed findings → append to `references/confirmed-patterns.md`
3. **Update exclusions**: False positives → append to `references/false-positives.md` with reason
4. **Update framework knowledge**: New framework insights → append to `references/framework-fingerprints.md`
5. **Record trajectory**: Save audit statistics for trend analysis

## Anti-Hallucination Rules

ALL findings MUST pass these verification checks:

1. **File path validation**: Every reported file MUST exist (verify with Glob before including in report)
2. **Code snippet verification**: Every code snippet MUST match the actual file content at the reported line number (verify with Read)
3. **Minimum tool calls**: Do NOT report findings without reading the actual source code — at least 3 Read/Grep calls per finding
4. **Cross-source validation**: Findings supported by BOTH tool results AND LLM analysis get HIGH confidence; LLM-only findings get NEEDS_VERIFY status
5. **Gray list**: If uncertain whether code is vulnerable, place in a separate "Needs Review" section rather than the main findings list
6. **No speculation**: Do NOT infer vulnerability from function names alone — read the actual implementation

## Output Format

Always output findings in the structured report format above. Group findings by severity. Include actionable remediation for every finding. Provide secure code examples. Include the Phase 3.5 coverage summary table.

## OWASP Top 10 (2021) Coverage Map

| OWASP ID | Category | Skill Categories |
|----------|----------|-----------------|
| A01:2021 | Broken Access Control | Cat 2 (Auth), Cat 6 (Path Traversal), Cat 14 (Open Redirect), Cat 17 (Mass Assignment) |
| A02:2021 | Cryptographic Failures | Cat 3 (Data Exposure), Cat 4 (Insecure Crypto) |
| A03:2021 | Injection | Cat 1 (SQLi, CMDi, XSS, LDAP, NoSQL, XML), Cat 11 (SSTI), Cat 15 (CRLF), Cat 16 (Log), Cat 22 (Email) |
| A04:2021 | Insecure Design | Cat 21 (Business Logic) |
| A05:2021 | Security Misconfiguration | Cat 10 (Misconfiguration), Cat 13 (XXE), Cat 20 (Clickjacking) |
| A06:2021 | Vulnerable Components | Phase 3 (Supply Chain) |
| A07:2021 | Auth Failures | Cat 2 (Auth), Cat 12 (CSRF) |
| A08:2021 | Data Integrity Failures | Cat 7 (Deserialization), Phase 3 (Supply Chain) |
| A09:2021 | Logging & Monitoring | Cat 16 (Log Injection) |
| A10:2021 | SSRF | Cat 5 (SSRF) |

## CWE Top 25 (2024) Coverage Map

| Rank | CWE ID | Name | Skill Category |
|------|--------|------|---------------|
| 1 | CWE-79 | XSS | Cat 1 |
| 2 | CWE-787 | Out-of-bounds Write | Cat 8 |
| 3 | CWE-89 | SQL Injection | Cat 1 |
| 4 | CWE-352 | CSRF | Cat 12 |
| 5 | CWE-22 | Path Traversal | Cat 6 |
| 6 | CWE-125 | Out-of-bounds Read | Cat 8 |
| 7 | CWE-78 | OS Command Injection | Cat 1 |
| 8 | CWE-416 | Use After Free | Cat 8 |
| 9 | CWE-862 | Missing Authorization | Cat 2 |
| 10 | CWE-434 | Unrestricted Upload | Cat 6 |
| 11 | CWE-94 | Code Injection | Cat 1, Cat 11 |
| 12 | CWE-20 | Improper Input Validation | Cat 1, Cat 17, Cat 19 |
| 13 | CWE-77 | Command Injection | Cat 1 |
| 14 | CWE-287 | Improper Authentication | Cat 2 |
| 15 | CWE-269 | Improper Privilege Management | Cat 2 |
| 16 | CWE-502 | Insecure Deserialization | Cat 7 |
| 17 | CWE-200 | Information Exposure | Cat 3 |
| 18 | CWE-863 | Incorrect Authorization | Cat 2 |
| 19 | CWE-918 | SSRF | Cat 5 |
| 20 | CWE-119 | Buffer Overflow | Cat 8 |
| 21 | CWE-476 | NULL Pointer Dereference | Cat 8 |
| 22 | CWE-190 | Integer Overflow | Cat 8 |
| 23 | CWE-362 | Race Condition | Cat 9 |
| 24 | CWE-601 | Open Redirect | Cat 14 |
| 25 | CWE-306 | Missing Authentication | Cat 2 |

## Language Support Matrix

| Vulnerability | Go | Python | Java | JS/TS | PHP | Ruby | Rust | C/C++ | C#/.NET | Kotlin | Swift |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SQL Injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Command Injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| XSS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | - | ✅ | ✅ | - |
| SSTI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | - | ✅ | - | - |
| XXE | - | ✅ | ✅ | - | ✅ | ✅ | - | ✅ | ✅ | ✅ | - |
| Deserialization | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| SSRF | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CSRF | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | - | ✅ | - | - |
| Auth Bypass | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Memory Safety | - | - | - | - | - | - | ✅ | ✅ | - | - | ✅ |
| Prototype Pollution | - | - | - | ✅ | - | - | - | - | - | - | - |
| Race Condition | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ReDoS | - | ✅ | ✅ | ✅ | ✅ | ✅ | - | - | ✅ | ✅ | - |
| Mass Assignment | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | - | ✅ | - | - |
| Log Injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Open Redirect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| Type Juggling | - | - | - | ✅ | ✅ | - | - | - | - | - | - |
| CRLF/Header Inj | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Business Logic | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| File Upload (Cat 23) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | - |
| Auth Deep Bypass (Cat 24) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| Modern Protocol (Cat 25) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| Privilege Escalation (Cat 26) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
