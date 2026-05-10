# Confirmed Vulnerability Patterns

Accumulated from verified audit findings. Each pattern was confirmed in a real audit and should be prioritized in future scans.

## How This File Works
- Entries are added automatically after Phase 6 feedback (user confirms a finding)
- Each entry includes: pattern, language, CWE, source audit, and grep/semgrep rule
- During Phase 0, these patterns are loaded and injected into Agent prompts
- Patterns here get HIGHER priority than generic SKILL.md rules

## Format
```
### [PATTERN-ID] Short description
- **Language**: Java/Python/Go/...
- **CWE**: CWE-XXX
- **Detection**: grep/semgrep pattern
- **Context**: When this pattern is dangerous
- **Source**: First confirmed in audit of [project] on [date]
```

## Patterns

(This file will be populated as audits are completed and findings confirmed)

### [PATTERN-001] Spring @Value with hardcoded default credentials
- **Language**: Java
- **CWE**: CWE-798 (Use of Hard-Coded Credentials)
- **Detection**: `grep -rn '@Value.*password.*:\|@Value.*secret.*:\|@Value.*[Kk]ey.*:' --include='*.java'`
- **Context**: Dangerous when the default value after `:` is a real credential (not empty). Example: `@Value("${redis.password:Admin123}")` — if config property is missing, hardcoded default is used in production.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-002] Jackson enableDefaultTyping in RedisConfig
- **Language**: Java
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Detection**: `grep -rn 'enableDefaultTyping\|activateDefaultTyping' --include='*.java'`
- **Context**: Critical when ObjectMapper with enableDefaultTyping is used as Redis serializer. Redis data is untrusted if any writer is compromised or Redis is network-accessible. Combined with gadget chains (commons-collections, c3p0, groovy) = RCE.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-003] XXL-Job empty or exposed accessToken
- **Language**: Java (config)
- **CWE**: CWE-798 / CWE-306
- **Detection**: `grep -rn 'xxl.job.accessToken' --include='*.yml' --include='*.properties'`
- **Context**: Empty or leaked accessToken (via Actuator /env) allows attackers to submit GLUE_SHELL jobs for arbitrary command execution on executor port.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-004] Druid StatViewServlet with weak/default credentials
- **Language**: Java
- **CWE**: CWE-798
- **Detection**: `grep -rn 'StatViewServlet\|loginUsername\|loginPassword' --include='*.java'`
- **Context**: Druid console exposes SQL queries, session info, datasource config. Default credentials (admin/admin, druid/druid) are commonly copy-pasted from docs. Check `allow` parameter — empty string means all IPs.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-005] MyBatis ${} with user-controlled input
- **Language**: Java (XML + annotations)
- **CWE**: CWE-89 (SQL Injection)
- **Detection**: `grep -rn '\${' --include='*.xml' | grep -i mapper` and `grep -rn '@Select.*\${\|@Update.*\${' --include='*.java'`
- **Context**: `${}` in MyBatis is raw string substitution. Safe only for hardcoded constants, never user input. Common: `ORDER BY ${column}`, `IN (${ids})`, `${signSql}` (entire SQL fragment injection).
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-006] RSA/AES private keys hardcoded in Java source
- **Language**: Java
- **CWE**: CWE-321 (Hard-Coded Cryptographic Key)
- **Detection**: `grep -rn 'MIIEv\|privateKeyStr\|AESKey\|signKey\|encryptKey' --include='*.java'`
- **Context**: Private keys as string constants in utility classes (RSAUtil, AESUtil, CryptoHelper). Extractable from compiled JARs via decompilation. Also check `Const.java` for key material fields.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-007] Auth interceptor overly broad excludePathPatterns
- **Language**: Java (Spring)
- **CWE**: CWE-862 (Missing Authorization)
- **Detection**: `grep -rn 'excludePathPatterns' --include='*.java'`
- **Context**: Spring HandlerInterceptor with broad excludes like `/actuator/**`, `/druid/**`, `/swagger/**`, `/test/**`. These paths bypass auth entirely. Check that excluded paths don't include sensitive endpoints.
- **Source**: Confirmed in Enterprise IoT project audit

### [PATTERN-008] Second-layer auth bypass via in-method passUrl array
- **Language**: Java (Spring custom interceptor)
- **CWE**: CWE-862 / CWE-287
- **Detection**: Look for HandlerInterceptor `preHandle` that compares request URI against an internal String[] / List before auth check. Example pattern:
  ```java
  for (int i = 0; i < Constant.passUrl.length; ++i) {
      if (url.equals(Constant.passUrl[i])) return true;  // skip auth
  }
  ```
- **Context**: Even if Spring `excludePathPatterns` is tight, a hand-rolled second-layer bypass list (often named `passUrl`, `freeUrl`, `noAuthUrl`) may include 30-50 additional endpoints including sensitive writes, exports, and token-issuing endpoints. Always enumerate full list and cross-reference with business sensitivity.
- **Source**: Confirmed in Enterprise visitor management system audit

### [PATTERN-009] Anonymous token minting via self-registration endpoint
- **Language**: Java (Spring)
- **CWE**: CWE-287 / CWE-639
- **Detection**: Look for `@RequestMapping` methods that (a) are in auth-bypass list, (b) construct `AuthToken` / JWT from `@RequestBody` fields including `userid`, (c) return the token in response.
- **Context**: Anonymous registration endpoints (addPersonInfo, register, signup) that trust user-supplied `userid` in request body and issue valid session tokens. Combined with no vertical authorization (RBAC missing), this yields full admin impersonation.
- **Source**: Confirmed in Enterprise visitor management system audit (anonymous registration endpoint)

### [PATTERN-010] "Check-but-no-return" broken authorization pattern
- **Language**: Java (Servlet-level auth)
- **CWE**: CWE-862 / CWE-670
- **Detection**: grep for methods that check token validity (`hashOperations.hasKey`, `token.isValid()`) followed by `response.getWriter().write("error")` without a subsequent `return;` statement. Regex hint: `response\.getWriter\(\)\.write\(".*token.*"\);?\s*[^r]` (no return after).
- **Context**: Controllers manually reimplement auth (instead of using interceptor) and write error response but forget to abort method execution. Subsequent business logic runs with user-controlled parameters → anonymous data access. Particularly common in Export* / Download* methods that bypass interceptor.
- **Source**: Confirmed in Enterprise visitor management system audit (10+ Export endpoints across multiple controllers)

### [PATTERN-011] Redis-key-is-AES-ciphertext token design
- **Language**: Java (auth pattern)
- **CWE**: CWE-287 / CWE-384
- **Detection**: Interceptor uses `redisTemplate.opsForHash().hasKey(rawToken, ...)` where rawToken is the AES-encrypted JSON itself (not a userid-based key). Combined with hardcoded AES key → if attacker can write to Redis OR knows the key and can produce any ciphertext that the server previously wrote, auth is bypassed.
- **Context**: Anti-pattern where token string (AES ciphertext) is both the Redis key and the authentication credential. Interceptor doesn't AES-decrypt — only checks key existence. AES key compromise + any legitimate token minting endpoint = full bypass.
- **Fix**: Use `userid` as Redis key; store token hash as value; interceptor must AES-decrypt and validate userid-token binding.
- **Source**: Confirmed in Enterprise visitor management system audit (token interceptor + 30+ token-issuing endpoints)

### [PATTERN-012] SAML XML parsing without DTD disable = XXE (pre-auth)
- **Language**: Java
- **CWE**: CWE-611
- **Detection**: `grep -rn 'DocumentBuilderFactory\|SAXParser\|XMLReader' --include='*.java' | xargs grep -L 'disallow-doctype-decl'`. Especially dangerous in SAML/SSO response parsers where DTD disable is often forgotten.
- **Context**: SAMLResponse parsing in oktaLogin/ssoLogin/samlCallback uses `DocumentBuilderFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`. Attack: inject external entity in SAMLResponse (Base64 in request body) → read files / SSRF before signature validation.
- **Source**: Confirmed in Enterprise visitor management system audit (XML parser utility called from SSO login handler)

### [PATTERN-013] sendVerifyCode/sendAuthCode returns authcode in HTTP response body — **CRITICAL account takeover primitive**
- **Language**: any (server-side API design flaw)
- **CWE**: CWE-200 (Information Exposure) + CWE-287 (Improper Authentication)
- **Detection**: Live-test the SMS/email code sending endpoint anonymously. If response body contains `authcode` / `code` / `verifyCode` / `otp` as plaintext → **instant account takeover primitive**.
  - Passive detection: `grep -rn '"authcode"\|"otpCode"\|"verifyCode"' backend_source` (if you have server code)
  - Active: `curl -X POST $API/sendVerifyCode -d 'phone=X&...'` and inspect JSON response
- **Context**: Happens when backend developers copy-paste code from tutorials that return the code for "testing", and forget to remove. Makes SMS interception unnecessary. Combined with forgeable sign (client-side MD5 with hardcoded salt), the attacker can: (1) compute sign offline, (2) POST sendVerifyCode to get authcode from response, (3) POST loginByCode/resetPassword/deleteAccount with the captured code. This is the **entire auth chain bypass** in 3 HTTP requests, no MITM required, no social engineering.
- **Combine with**: PATTERN-014 (forgeable client-side sign with static salts).
- **Source**: Confirmed in IoT health app audit (SMS code endpoint returns authcode in response body)

### [PATTERN-014] MD5 signature with hardcoded dual-salt across APK family
- **Language**: any mobile app
- **CWE**: CWE-798 (Hard-Coded Cryptographic Key) + CWE-639 (Authorization Bypass)
- **Detection**:
  - `grep -rn 'MessageDigest\.getInstance.*MD5\|hashlib\.md5' source/` then look for string constants passed to the hash function
  - Suspicious pattern: two MD5 calls with literal string salts, one wrapping the other's output
  - String pool extraction: `strings apk-unzip/classes*.dex | grep -iE 'salt|secret|key' -C 2`
- **Context**: Mobile SDKs often use `MD5(MD5(phone+time+salt1) + salt2)` to "sign" sensitive calls (SMS, reset password). Both salts are compiled into APK → trivially recoverable via `jadx`. Across APK families (same vendor, multiple apps), the salts are often REUSED → compromising one APK compromises entire ecosystem.
- **Source**: IoT health device ecosystem (multiple apps from same vendor share identical MD5 salts), confirmed in IoT health app audit.

### [PATTERN-015] Android FileProvider `<root-path path="."/>` — full filesystem exposure
- **Language**: Android
- **CWE**: CWE-22 (Path Traversal) + CWE-552
- **Detection**: `grep -rn '<root-path' apk-unzip/res/xml/` — any `<root-path>` element in `file_paths.xml` is a serious finding. Worst case is `path="."` or `path="/"`.
- **Context**: FileProvider's `<root-path>` grants URI permission to entire root of device (including `/data/data/<pkg>/shared_prefs/`, `/data/data/<pkg>/databases/`). Any code path that calls `getUriForFile()` with an attacker-influenced File arg → arbitrary file read via content URI. Often combined with exported Activities that accept Intent extras.
- **Fix**: Use `<files-path>`, `<cache-path>`, `<external-files-path>` with specific `path` sub-directories; never `<root-path>`.
- **Source**: IoT health app audit (file_paths.xml exposed root-path)

### [PATTERN-016] BridgeWebView.setWebContentsDebuggingEnabled(true) without BuildConfig.DEBUG guard
- **Language**: Android (WebView)
- **CWE**: CWE-489 (Active Debug Code)
- **Detection**: `grep -rn 'setWebContentsDebuggingEnabled' sources/` — any call NOT wrapped in `if (BuildConfig.DEBUG)` or `if (isDebug)`. The jsbridge `BridgeWebView` default implementation always enables on SDK 19+.
- **Context**: With remote debugging enabled in release, anyone with ADB over USB (or network ADB) can attach Chrome DevTools to the running WebView, dump DOM / cookies / localStorage including stored tokens, and execute arbitrary JS in the WebView context. Combined with tokenLogin-style URLs that pass `?token=xxx` in query strings, this means full account exposure on any developer-accessible device.
- **Source**: IoT health app audit (WebView bridge class)

### [PATTERN-017] Android OkHttp Interceptor attaches token to ALL requests unconditionally
- **Language**: Android (OkHttp)
- **CWE**: CWE-200 (Information Exposure)
- **Detection**: `grep -rln 'implements Interceptor\|extends Interceptor' sources/` → inspect each `intercept()` method. Red flag: reads token from SharedPreferences and unconditionally `builder.addHeader("token", token)` without endpoint whitelist.
- **Context**: When combined with HTTP cleartext main API, the interceptor sends real bearer tokens attached to ALL outgoing requests — including anonymous endpoints like `checkExist`, `sendVerifyCode`, `resetPassword`. MITM on any call captures the token, even when the user is just browsing community pages or getting OTP codes. The fix is to either (a) maintain an endpoint allow-list for token-requiring paths, or (b) move to HTTPS + cert pinning so the on-wire exposure is moot.
- **Source**: IoT health app audit (HTTP interceptor class)
