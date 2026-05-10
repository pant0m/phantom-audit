---
name: ctf-rce-hunting
description: "CTF / authorized pentest RCE hunting playbook. Systematic methodology for chasing RCE on a known target with available decompiled code. Combines reconnaissance, decompilation-driven sink discovery, multi-angle probing, and PoC chain construction. Use ONLY in authorized CTF / lab / pentest engagements."
license: MIT
version: 1.0.0
user_invocable: true
---

# CTF RCE Hunting Playbook

A systematic methodology for the situation where:
1. You have an authorized CTF/lab target with a known IP and product
2. You have access to source code or decompiled binaries
3. You have time-bounded objective: prove RCE works
4. You may face rate limits, lockouts, WAFs

## Core Principle

**Don't randomly probe. Build a complete attack surface map first, then attack the weakest link.**

## Phase 1: Re-baseline (5 minutes)

When stuck:
- Test if your IP is locked out (try a request that doesn't trigger lockout, e.g. GET /favicon.ico)
- Test from a different source if possible
- Check the target is still up + not under reset
- Re-list any rate-limit / lockout state

## Phase 2: Surface Mapping (parallelizable)

Map ALL attack surface, not just the obvious one:

### 2.1 Port scan
- Beyond the known web port, scan the host: 80, 443, 22, 445, 3389, 5985, 8000-8999, 9000-9999
- The target product often ships with companion services (admin port, IPC port, agent port)

### 2.2 Endpoint enumeration
- Get all paths the product can serve from web.config / route table
- Cross-reference with decompiled code for hidden ops
- Look for: `*.rsb`, `*.rsc`, `*.rsd`, `*.rst`, `.aspx`, `.ashx`, `.asmx`, `.svc`, `_static_`, `_admin_`
- Hidden endpoints: backup, debug, healthcheck, swagger, openapi, metrics, prometheus
- Mobile/CLI endpoints: api/v1, api/v2, /mobile, /cli

### 2.3 Header/cookie analysis
- All response headers indicate framework, version, auth state
- Custom headers (like `x-cdata-login`) are gold (product fingerprint)
- Cookie names indicate session strategy

### 2.4 JS bundle analysis
- Download all JS bundles (often has hardcoded API endpoints, default tokens, internal URLs)
- `runtime.bundle.js`, `react.bundle.js`, `vendors.bundle.js` etc.
- Look for: `apiUrl`, `endpoint`, `token`, `secret`, `default*Url`, `internal*`

## Phase 3: Decompilation-Driven Sink Hunt

For .NET targets:
1. Install `ilspycmd` via dotnet tool: `dotnet tool install -g ilspycmd`
2. May need .NET 6 runtime: `brew install dotnet@6` then `DOTNET_ROOT=/opt/homebrew/opt/dotnet@6/libexec`
3. Decompile largest DLL first (it's usually the main logic)
4. Output may be 1M+ lines - use grep aggressively, never read whole file

### 3.1 RCE Sinks to grep
```bash
SINKS='Process\.Start|new Process\(|StartInfo\.FileName|powershell|cmd\.exe|/bin/sh|exec\(|system\(|popen\(|Eval\(|CompileAssembly|CSharpCodeProvider|Roslyn|Assembly\.Load|MethodInfo.*Invoke|Activator\.CreateInstance|InvokeMember|Reflection|BinaryFormatter|TypeNameHandling|ObjectInputStream|JsonConvert\.DeserializeObject|YamlDeserializer'

PYEXEC='python|PythonExec|PythonRuntime|PyObject|exec_python'

FILEWRITE='File\.Open|File\.WriteAll|FileStream|File\.Create|StreamWriter|Path\.Combine|MapPath|WriteAllBytes'

LOAD='Assembly\.LoadFrom|Assembly\.LoadFile|AppDomain\.Load'
```

### 3.2 For each sink, trace backwards
- Who calls this? (grep for method name)
- What's the auth gate? (look for restrict role / Authorize attribute)
- Is the sink parameter user-controlled? (trace input flow)

### 3.3 Identify "auth-free" sinks
The fastest path is a sink that's reachable from `/pub/*` or anonymous endpoints. Look for:
- Anonymous handlers that internally `Call("...")` arbitrary internal ops
- Template engines that evaluate user input
- Any `op` or `feed` invocation where the op name itself is user-controlled

## Phase 4: Auth Bypass Discovery

If RCE requires auth, look for:
- Default credentials (often in install scripts, README, vendor docs)
- Weak credential brute force (with IP rotation if lockout is per-IP)
- JWT signing key disclosure
- Token in URL parameter (logs/Referer leak)
- Authentication bypass in middleware (case sensitivity, encoding, double encoding)
- Hidden setup/install endpoints that don't check auth
- Race conditions in user creation/setup
- File-based auth (if you can write a user record file directly)

## Phase 5: Multi-vector parallel verification

Spawn parallel sub-agents, each focusing on ONE vector:
- Agent A: brute force credentials
- Agent B: AS2/EDI fuzzing
- Agent C: SSO/OIDC abuse
- Agent D: Path traversal / template injection
- Agent E: External port discovery

Each agent reports REAL/MITIGATED/CONDITIONAL with PoC.

## Phase 6: Chain Construction

Few RCEs are single-step. Common chains:
- Info Disclosure → Token Discovery → Authenticated RCE
- Anonymous File Write → Trigger Compilation → RCE
- Open Redirect → SSO Token Theft → Admin Login → Auth'd RCE
- SSRF → Internal Service → RCE

Build a chain, document each step's success criterion.

## Phase 7: PoC Construction

When attempting RCE, prove it succinctly:
- Cause an out-of-band signal: DNS lookup, HTTP callback to attacker-controlled URL
- Read a known file: `/etc/passwd`, `C:\Windows\win.ini`, `web.config`
- Time delay: `sleep 5`
- Stdout capture if possible
- Persist nothing unless explicitly required

## Anti-patterns

- Don't keep brute forcing after lockout — rotate user/source
- Don't burn time on speculative paths without code evidence
- Don't try the same payload class on every endpoint — cluster by sink type
- Don't ignore "200 OK" with empty body — it may be silent success or error masking
- Don't ignore HTTP redirects — they reveal real handlers

## CTF-specific tips

- CTF targets often have intentional "easy path" + "hard path"
- Vendor's documentation is part of the attack surface (default creds, setup wizard URLs)
- README files in deployed dir may have flag/hint
- Check for `flag.txt`, `FLAG`, `secret.txt` in known web roots
- Check `appsettings.json` / `web.config` / `*.bak` for hints
- The CTF judge said "RCE exists" — that's a hint the path is documented or in a known CVE

## Output

Each session should produce:
- `ATTACK_SURFACE.md` — full URL/handler/auth matrix
- `SINK_CATALOG.md` — every dangerous code sink with location
- `CHAIN.md` — the verified RCE chain
- `POC.sh` — reproducible PoC script
