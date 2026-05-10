# Phase 2: Pre-Scan Tool Commands

Run these commands BEFORE LLM deep analysis. Results feed into Phase 3 as structured candidate lists.

## Auto-detect and run applicable tools

### Step 0: JAR/WAR Decompilation (if applicable)

If the target is a compiled artifact (`.jar`, `.war`, `.aar`), decompile it first. See `scripts/jar-decompile.md` for the full pipeline. Quick inline version:

```bash
if [[ "$TARGET_DIR" == *.jar || "$TARGET_DIR" == *.war || "$TARGET_DIR" == *.aar ]]; then
  mkdir -p /tmp/audit-decompile/{extracted,src}
  unzip -o -q "$TARGET_DIR" -d /tmp/audit-decompile/extracted

  # Download CFR if not present
  [ ! -f /tmp/cfr.jar ] && curl -sL -o /tmp/cfr.jar \
    https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar

  # Decompile ALL .class files (including inner classes with $)
  find /tmp/audit-decompile/extracted -name '*.class' \
    -not -path '*/springframework/boot/loader/*' | while read f; do
    java -jar /tmp/cfr.jar "$f" --outputdir /tmp/audit-decompile/src --silent true 2>/dev/null
  done

  # Copy config files
  find /tmp/audit-decompile/extracted -type f \
    \( -name '*.xml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.properties' -o -name '*.json' \) \
    -exec cp --parents {} /tmp/audit-decompile/src/ \; 2>/dev/null
  cp -r /tmp/audit-decompile/extracted/META-INF /tmp/audit-decompile/src/ 2>/dev/null

  TARGET_DIR="/tmp/audit-decompile/src"
  TOTAL_CLASS=$(find /tmp/audit-decompile/extracted -name '*.class' | wc -l)
  TOTAL_JAVA=$(find $TARGET_DIR -name '*.java' | wc -l)
  echo "Decompiled: $TOTAL_CLASS classes -> $TOTAL_JAVA Java files ($(( TOTAL_JAVA * 100 / TOTAL_CLASS ))%)"
fi
```

### Step 1: Semgrep (All languages)
```bash
semgrep scan --config p/security-audit --config p/owasp-top-ten \
  --json --quiet --max-target-bytes 1000000 \
  TARGET_DIR/ > /tmp/semgrep_results.json 2>/dev/null
```

### Step 2: Gitleaks (Secret detection)
```bash
gitleaks detect --source TARGET_DIR/ --no-git \
  --report-format json --report-path /tmp/gitleaks_results.json 2>/dev/null
```

### Step 3: Dependency analysis (language-specific)

**Java (pom.xml/build.gradle)**:
```bash
osv-scanner scan --format json TARGET_DIR/ > /tmp/osv_results.json 2>/dev/null
```

**Python (requirements.txt/pyproject.toml)**:
```bash
bandit -r TARGET_DIR/ -f json -o /tmp/bandit_results.json 2>/dev/null
osv-scanner scan --format json TARGET_DIR/ > /tmp/osv_results.json 2>/dev/null
```

**JavaScript/TypeScript (package.json)**:
```bash
osv-scanner scan --format json TARGET_DIR/ > /tmp/osv_results.json 2>/dev/null
```

**Go (go.mod)**:
```bash
osv-scanner scan --format json TARGET_DIR/ > /tmp/osv_results.json 2>/dev/null
```

## Output Processing

After running tools, parse results into a unified candidate list:
1. Read each JSON output file
2. Extract: file_path, line_number, rule_id, severity, message, code_snippet
3. Group by vulnerability category (map rule_id to our 22 categories)
4. Pass grouped candidates to the corresponding Phase 3 Agents

### Step 4: Java/Spring Configuration Grep (if Java project detected)

```bash
if find "$TARGET_DIR" -maxdepth 3 \( -name 'pom.xml' -o -name 'build.gradle' -o -name '*.java' \) | head -1 | grep -q .; then
  echo "=== Java Config Scan ==="

  # Configuration classes
  grep -rl '@Configuration\|@SpringBootApplication' "$TARGET_DIR" --include='*.java' > /tmp/java_config_classes.txt 2>/dev/null

  # Hardcoded credentials (extended patterns)
  grep -rn 'password\s*=\s*["'"'"']\|[Ss]ecret\s*=\s*["'"'"']\|[Tt]oken\s*=\s*["'"'"']' \
    "$TARGET_DIR" --include='*.java' --include='*.yml' --include='*.properties' \
    > /tmp/java_credentials.txt 2>/dev/null

  # Spring @Value defaults with sensitive names
  grep -rn '@Value.*password\|@Value.*secret\|@Value.*[Kk]ey' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_value_defaults.txt 2>/dev/null

  # RSA/private keys in code
  grep -rn 'MIIEv\|MIIG\|BEGIN.*PRIVATE\|privateKeyStr\|AESKey\|signKey\|encryptKey' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_private_keys.txt 2>/dev/null

  # Jackson enableDefaultTyping
  grep -rn 'enableDefaultTyping\|activateDefaultTyping\|NON_FINAL' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_jackson_typing.txt 2>/dev/null

  # XXL-Job config
  grep -rn 'xxl.job.accessToken\|XxlJobSpringExecutor\|GLUE_SHELL\|GLUE_GROOVY' \
    "$TARGET_DIR" --include='*.java' --include='*.yml' --include='*.properties' > /tmp/java_xxljob.txt 2>/dev/null

  # Druid console
  grep -rn 'StatViewServlet\|DruidStatViewServlet\|loginUsername\|loginPassword' \
    "$TARGET_DIR" --include='*.java' --include='*.yml' --include='*.properties' > /tmp/java_druid.txt 2>/dev/null

  # SQL injection in Java code (beyond MyBatis XML)
  grep -rn 'Statement\.execute\|createStatement()\|createNativeQuery.*+' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_sql_injection.txt 2>/dev/null

  # MyBatis ${} in XML AND annotations
  grep -rn '\${' "$TARGET_DIR" --include='*.xml' | grep -i 'mapper\|dao\|sql' > /tmp/java_mybatis_xml.txt 2>/dev/null
  grep -rn '@Select.*\${\|@Update.*\${\|@Delete.*\${\|@Insert.*\${' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_mybatis_anno.txt 2>/dev/null

  # Auth interceptor excludes
  grep -rn 'excludePathPatterns\|addPathPatterns' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_interceptor_paths.txt 2>/dev/null

  # Actuator exposure
  grep -rn 'management.endpoints.web.exposure\|management.endpoint' \
    "$TARGET_DIR" --include='*.yml' --include='*.yaml' --include='*.properties' > /tmp/java_actuator.txt 2>/dev/null

  # CORS config
  grep -rn 'addAllowedOrigin\|allowedOrigins\|setAllowCredentials' \
    "$TARGET_DIR" --include='*.java' > /tmp/java_cors.txt 2>/dev/null

  echo "Java config scan complete. Check /tmp/java_*.txt for results."
fi
```

Feed these results into Phase 3 Agents alongside Semgrep/Gitleaks output.

## Tool Availability Check
Before running, verify tools are installed:
```bash
which semgrep && which gitleaks && which osv-scanner && which bandit
```
If a tool is missing, skip it and note in the coverage report.
