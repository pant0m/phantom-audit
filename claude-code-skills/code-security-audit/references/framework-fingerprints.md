# Framework Security Fingerprints

Framework-specific security knowledge accumulated from audits. When a target project matches a known framework fingerprint, the corresponding security knowledge is automatically loaded.

## How This File Works
- Entries added after each audit extracts framework-specific insights
- During Phase 1 (recon), the detected tech stack is matched against these fingerprints
- Matching fingerprints are injected into Phase 3 Agent prompts
- This is how the system "remembers" framework-specific gotchas

## Format
```
### [FW-ID] Framework Name + Version Range
- **Detection**: How to identify this framework (files, dependencies, patterns)
- **Known risks**: Security issues specific to this version
- **Default security posture**: What's secure by default, what's not
- **Common misconfigurations**: Frequently seen mistakes
- **Auth model**: How authentication typically works
```

## Fingerprints

### [FW-001] Spring Boot 2.0.x - 2.1.x
- **Detection**: `pom.xml` contains `spring-boot-starter-parent` version `2.0.*` or `2.1.*`
- **Known risks**:
  - Jackson 2.9.x bundled — `enableDefaultTyping` may allow deserialization RCE
  - Spring Security not included by default — custom auth interceptors common
  - Actuator endpoints may be exposed without authentication
  - CORS `allowedOrigins("*")` + `allowCredentials(true)` combination allowed (fixed in later versions)
- **Default security posture**: CSRF protection OFF if no Spring Security; No content-type validation on file uploads
- **Common misconfigurations**:
  - OPT-IN authentication (only annotated endpoints require auth) instead of OPT-OUT
  - Swagger UI exposed in production (`/v2/api-docs`, `/swagger-ui.html`)
  - Test controllers deployed to production
  - JWT signing keys hardcoded in application.yml
- **Auth model**: Often custom `HandlerInterceptor` + annotation-based (`@AuthToken`, `@RequiresAuth`)
- **Source**: Enterprise IoT project audit

### [FW-002] Spring Boot 2.7.x - 3.x
- **Detection**: `pom.xml` contains `spring-boot-starter-parent` version `2.7.*` or `3.*`
- **Known risks**:
  - Jackson `enableDefaultTyping` disabled by default (safer than 2.1.x)
  - Log4j2 may still be present in older 2.7.x — check for CVE-2021-44228 mitigation
- **Default security posture**: CSRF protection ON if Spring Security present; Actuator requires authentication by default in 3.x
- **Common misconfigurations**:
  - `@CrossOrigin` annotation without explicit origins
  - Missing `@PreAuthorize` on sensitive endpoints
- **Source**: General knowledge

(More fingerprints will be added as audits are completed)

### [FW-003] Jackson with enableDefaultTyping (any version)
- **Detection**: `jackson-databind` in dependencies; Java source contains `enableDefaultTyping` or `activateDefaultTyping`
- **Known risks**:
  - `enableDefaultTyping(NON_FINAL)` allows deserialization of arbitrary classes via JSON `@type` metadata
  - When this ObjectMapper is used in Redis serialization (`GenericJackson2JsonRedisSerializer`), RPC, or MQ message handling, any untrusted input triggers RCE
  - Known gadget chains: commons-collections (InvokerTransformer), commons-beanutils (BeanComparator), C3P0, JNDI lookup via JdbcRowSetImpl
  - Even `NON_FINAL` is exploitable — most gadget classes are non-final
- **Default security posture**: Jackson does NOT enable polymorphic typing by default — finding this in code is always HIGH or CRITICAL
- **Common misconfigurations**:
  - RedisConfig using `ObjectMapper.enableDefaultTyping(NON_FINAL)` then passing to `GenericJackson2JsonRedisSerializer`
  - API response ObjectMapper shared with Redis/MQ ObjectMapper
- **Source**: Enterprise IoT project audit

### [FW-004] XXL-Job Executor (2.x)
- **Detection**: `xxl-job-core` in dependencies; config contains `xxl.job.executor`
- **Known risks**:
  - Executor `/run` endpoint accepts `glueType` = `GLUE_SHELL` (bash), `GLUE_GROOVY` (Groovy) — arbitrary code execution
  - `accessToken` is the ONLY authentication — if empty, blank, or leaked via Actuator /env, attackers submit arbitrary jobs
  - Default executor port is 9999, often bound to 0.0.0.0
  - Executor does not validate that caller is the legitimate admin server
- **Default security posture**: `accessToken` defaults to empty in many configurations — unauthenticated by default
- **Common misconfigurations**:
  - `accessToken` stored in application.yml and exposed via Actuator /env
  - Executor bound to all interfaces instead of localhost
- **Source**: Enterprise IoT project audit

### [FW-005] Alibaba Druid DataSource (1.x)
- **Detection**: `druid-spring-boot-starter` or `druid` in dependencies; Java contains `DruidDataSource` or `StatViewServlet`
- **Known risks**:
  - `StatViewServlet` exposes web console at `/druid/` with SQL query logs, active sessions, datasource config
  - Default credentials often `admin/admin` or copied from tutorials into production
  - SQL monitoring shows full query text including parameter values (may contain PII, tokens)
  - `resetEnable=true` allows stat reset (operational DoS)
- **Default security posture**: StatViewServlet has NO authentication by default
- **Common misconfigurations**:
  - Registering StatViewServlet without loginUsername/loginPassword
  - Setting `allow` IP filter to empty string (allows all IPs)
  - Wall filter disabled — no SQL restriction on monitoring page
- **Source**: Enterprise IoT project audit

### [FW-006] MyBatis ${} Injection Patterns
- **Detection**: `mybatis` in dependencies; XML files in mapper/dao directories contain `${`
- **Known risks**:
  - `${}` performs direct string substitution (no escaping) — equivalent to raw SQL concatenation
  - Common patterns: `ORDER BY ${column}`, `LIKE '%${keyword}%'`, `IN (${ids})`, `${tableName}`, `${signSql}` (entire SQL fragment)
  - `#{}` is safe but CANNOT be used for column/table names or ORDER BY — developers use `${}` as workaround
  - Also check `@Select`/`@Update`/`@Insert`/`@Delete` annotations in Java interfaces
- **Default security posture**: MyBatis does not warn when `${}` is used
- **Common misconfigurations**:
  - Sort column from request parameter directly to `ORDER BY ${column}`
  - Dynamic table name from user input in multi-tenant apps
  - Building IN clauses via `${ids}` instead of `<foreach>` with `#{}`
- **Source**: Enterprise IoT project audit

### [FW-007] Custom AES Token Scheme (visitor management pattern)
- **Detection**: `grep -rn 'X-COOLVISIT-TOKEN\|getAESEncoderTokenString\|AESUtil.decode\|AESUtil.encode' --include='*.java'`; ObjectMapper.readValue converting decoded string to `AuthToken` class.
- **Known risks**:
  - AES key typically hardcoded (e.g. `"<hardcoded-key-redacted>"`) and reused across all token operations
  - `AESUtil.getKey()` uses `SecureRandom.getInstance("SHA1PRNG").setSeed(passwordBytes)` + KeyGenerator.init(128) → deterministic key derivation
  - `Cipher.getInstance("AES")` defaults to AES/ECB/PKCS5Padding
  - Interceptor stores Redis key = AES ciphertext; doesn't re-decrypt for validation
- **Default security posture**: Completely broken — WAR decompilation yields the AES key, giving attacker token-forgery capability for any userid issued via legitimate endpoints
- **Common misconfigurations**: Combined with no RBAC layer (only token-existence check) → single-tier auth; combined with anonymous self-registration endpoint → instant full impersonation
- **Source**: Enterprise visitor management system audit

### [FW-008] Camunda 7.14+ BPMN Deployment RCE via Groovy/JS Script Task
- **Detection**: `grep -rl 'camunda-engine\|repositoryService.createDeployment' --include='*.java'`
- **Known risks**:
  - Camunda enables Groovy and JavaScript ScriptEngines by default
  - Any endpoint that accepts .bpmn uploads + calls `createDeployment().addInputStream().deploy()` enables RCE via `<bpmn:scriptTask scriptFormat="groovy">`
  - Groovy script body: `["sh","-c","..."].execute().waitFor()` executes arbitrary OS commands
  - Even internal-only deployment endpoints are risky when combined with token-forgery vulnerabilities
- **Default security posture**: Script engine enabled, no script whitelist, no BPMN signature verification
- **Mitigation**: `ProcessEngineConfiguration.setExpressionManager` with scripting disabled; restrict deployments to specific admin role with separate auth
- **Source**: Enterprise visitor management system audit

### [FW-009] `/templates/**` + JSP bypass in Spring Boot WAR
- **Detection**: Check Spring config for `excludePathPatterns` containing `/templates/**`; check WEB-INF/classes/templates for `.jsp` files
- **Known risks**:
  - Leftover dev JSPs (Alipay/WeChat/WebSocket test pages) often remain accessible anonymously
  - JSP scriptlets execute server-side → any user-input reflection = RCE
  - Template paths leak internal architecture and dev URLs
- **Source**: Enterprise visitor management system audit
