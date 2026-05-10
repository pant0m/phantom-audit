# JAR/WAR/AAR Decompilation Pipeline

Standalone guide for decompiling compiled Java artifacts before security audit. Referenced by Phase 1.5 in SKILL.md.

## Prerequisites
- `java` runtime (JDK 8+)
- `unzip` command
- Internet access (to download CFR if not present) OR pre-downloaded decompiler

## Decompiler Priority Order

| Tool | Pros | Cons | Install |
|------|------|------|---------|
| CFR 0.152 | Best output quality, handles lambdas/inner classes well, single JAR | Slower on large codebases | `curl -L -o /tmp/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar` |
| Procyon | Good generics handling | Less maintained | `brew install procyon-decompiler` or download JAR |
| Fernflower | Bundled with IntelliJ | Output can be less readable | Located in IntelliJ installation |
| JADX | Good for Android (APK/AAR), GUI available | Slower for pure JAR | `brew install jadx` |

## Full Pipeline

### Step 1: Extract
```bash
TARGET="path/to/target.jar"
WORKDIR="/tmp/audit-decompile"
mkdir -p "$WORKDIR"/{extracted,src}

unzip -o -q "$TARGET" -d "$WORKDIR/extracted"

# Count ALL class files including inner classes ($):
TOTAL_CLASS=$(find "$WORKDIR/extracted" -name '*.class' | wc -l)
INNER_CLASS=$(find "$WORKDIR/extracted" -name '*$*' -name '*.class' | wc -l)
echo "Total .class files: $TOTAL_CLASS (including $INNER_CLASS inner classes)"
```

### Step 2: Decompile ALL classes
```bash
# Using CFR — decompile every .class file including inner classes:
java -jar /tmp/cfr.jar "$WORKDIR/extracted" \
  --outputdir "$WORKDIR/src" \
  --silent true \
  --caseinsensitivefs false \
  --removeboilerplate true \
  --decodefinally true \
  --decodelambdas true \
  2>/dev/null

TOTAL_JAVA=$(find "$WORKDIR/src" -name '*.java' | wc -l)
echo "Decompiled: $TOTAL_JAVA / $TOTAL_CLASS ($(( TOTAL_JAVA * 100 / TOTAL_CLASS ))%)"
```

If CFR cannot decompile the directory as a whole, decompile individual class files:
```bash
find "$WORKDIR/extracted" -name '*.class' | while read f; do
  java -jar /tmp/cfr.jar "$f" --outputdir "$WORKDIR/src" --silent true 2>/dev/null
done
```

### Step 3: Handle decompilation failures
```bash
# Find .class files that did not produce .java output
find "$WORKDIR/extracted" -name '*.class' | while read classfile; do
  javafile=$(echo "$classfile" | sed "s|$WORKDIR/extracted|$WORKDIR/src|" | sed 's/\.class$/.java/')
  if [ ! -f "$javafile" ]; then
    echo "$classfile" >> "$WORKDIR/failed_decompile.txt"
  fi
done

# Retry failed files individually with fallback decompiler
if [ -f "$WORKDIR/failed_decompile.txt" ]; then
  FAILED=$(wc -l < "$WORKDIR/failed_decompile.txt")
  echo "Retrying $FAILED failed files individually..."
  while read classfile; do
    java -jar /tmp/cfr.jar "$classfile" --outputdir "$WORKDIR/src" --silent true 2>/dev/null
  done < "$WORKDIR/failed_decompile.txt"
fi
```

### Step 4: Extract configuration resources
```bash
# XML configs (Spring, MyBatis mappers, logback, etc.)
find "$WORKDIR/extracted" -type f -name '*.xml' -exec cp --parents {} "$WORKDIR/src/" \; 2>/dev/null

# YAML/Properties (Spring Boot config)
find "$WORKDIR/extracted" -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.properties' \) \
  -exec cp --parents {} "$WORKDIR/src/" \; 2>/dev/null

# Template files (Velocity, Freemarker, Thymeleaf)
find "$WORKDIR/extracted" -type f \( -name '*.ftl' -o -name '*.html' -o -name '*.vm' \) \
  -exec cp --parents {} "$WORKDIR/src/" \; 2>/dev/null

# SQL files
find "$WORKDIR/extracted" -type f -name '*.sql' -exec cp --parents {} "$WORKDIR/src/" \; 2>/dev/null

# JSON configs
find "$WORKDIR/extracted" -type f -name '*.json' -exec cp --parents {} "$WORKDIR/src/" \; 2>/dev/null

# META-INF (contains pom.xml, MANIFEST.MF, spring.factories)
cp -r "$WORKDIR/extracted/META-INF" "$WORKDIR/src/" 2>/dev/null

# Extract embedded pom.xml for dependency analysis
find "$WORKDIR/extracted" -name 'pom.xml' -exec cp {} "$WORKDIR/src/pom.xml" \; 2>/dev/null
find "$WORKDIR/extracted" -name 'pom.properties' -exec cat {} \; > "$WORKDIR/src/dependency-info.txt" 2>/dev/null
```

### Step 5: Coverage gate
```bash
FINAL_JAVA=$(find "$WORKDIR/src" -name '*.java' | wc -l)
COVERAGE=$(( FINAL_JAVA * 100 / TOTAL_CLASS ))
echo "Final decompilation coverage: $FINAL_JAVA / $TOTAL_CLASS ($COVERAGE%)"

if [ "$COVERAGE" -lt 90 ]; then
  echo "WARNING: Coverage below 90%. Listing undecompiled files:"
  cat "$WORKDIR/failed_decompile.txt" 2>/dev/null
  echo "Consider using a different decompiler or manual review of failed files."
fi
```

### Step 6: Set target for audit
```bash
export TARGET_DIR="$WORKDIR/src"
echo "Audit target set to: $TARGET_DIR"
```

## Inner Class Importance

**CRITICAL: Do NOT skip files with `$` in their names.** These are inner classes and include:

| Pattern | Meaning | Security Relevance |
|---------|---------|-------------------|
| `Foo$Bar.class` | Named inner class `Bar` inside `Foo` | May contain auth logic, callbacks, config |
| `Foo$1.class` | Anonymous inner class (1st) | Often Runnable/Callable with business logic |
| `Foo$Bar$Baz.class` | Nested inner class | Configuration builders, security contexts |
| `Foo$$Lambda$1.class` | Lambda implementation | May capture credentials in closure |
| `Foo$Builder.class` | Builder pattern | Sets security parameters |

Common example: `RedisConfig$1.class` may contain the actual `ObjectMapper` configuration with `enableDefaultTyping` — skipping it means missing a CRITICAL RCE vulnerability.

## Graceful Degradation

If `java` is not available:
1. Report that JAR decompilation requires a Java runtime
2. Ask the user to either: (a) install Java, (b) provide decompiled source, or (c) accept reduced audit coverage
3. If proceeding without decompilation: scan only extracted XML/YAML/properties config files (Step 4 can run without Java)
4. Mark the audit report as "PARTIAL — compiled code not analyzed" with the coverage gap documented

## Spring Boot Fat JAR Notes

Spring Boot fat JARs have this structure:
```
BOOT-INF/
  classes/       <- application code, decompile ALL .class files here
  lib/           <- dependency JARs (for version checking, NOT decompilation)
META-INF/
  MANIFEST.MF    <- contains Start-Class, Spring-Boot-Version
org/springframework/boot/loader/  <- Spring Boot loader, skip decompilation
```
Focus decompilation on `BOOT-INF/classes/`. Only list `BOOT-INF/lib/*.jar` names for dependency version analysis.

## WAR-Specific Notes

WAR files have additional structure:
```
WEB-INF/
  classes/       <- decompile these .class files
  lib/           <- JAR dependencies (list for version checking)
  web.xml        <- servlet mappings, security constraints, filter config
```
Always check `WEB-INF/web.xml` for servlet-level security configuration.
