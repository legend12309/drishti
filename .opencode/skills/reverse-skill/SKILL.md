---
name: reverse-skill
description: Cybersecurity and reverse engineering skill router with 80+ specialist modules for vulnerability analysis, malware analysis, binary analysis, penetration testing, and security research. Use for authorized security analysis, scanner integration, vulnerability analysis, and reverse engineering tasks.
---

# Reverse Engineering Skills Router

This skill provides access to the reverse-skill repository at `D:\drishti\tools\reverse-skill` which contains 80+ specialist cybersecurity modules organized under `skills/`.

## Available Specialist Skills

| Skill | Directory | Use Case |
|-------|-----------|----------|
| API Security Testing | `skills/api-security/` | REST/GraphQL/WebSocket security: BOLA/IDOR, JWT/OAuth attacks |
| Binary Diff | `skills/binary-diff/` | Cross-version symbol migration, function name migration |
| Binary Ninja Reverse | `skills/binary-ninja-reverse/` | HLIL/MLIL/LLIL analysis, Python API |
| Browser Automation | `skills/browser-automation/` | Playwright + Windows UIA/CUA desktop automation |
| Cloud/K8s Security | `skills/cloud-k8s/` | IMDS/IAM, container escapes, Kubernetes RBAC |
| Code Audit | `skills/code-audit/` | Semgrep/CodeQL, white-box, dangerous API review |
| CTF Sandbox | `skills/ctf-sandbox/` | CTF challenges, sidecar orchestrator |
| Digital Forensics | `skills/digital-forensics/` | Memory/disk timelines, PCAP analysis, IR preservation |
| EDR Bypass Reverse | `skills/edr-bypass-re/` | EDR hook table/ETW/AMSI reverse, syscall techniques |
| Firmware Pentest | `skills/firmware-pentest/` | OWASP FSTM: extract→EMBA→Firmadyne/QEMU→AFL++→exploit |
| Ghidra Reverse | `skills/ghidra-reverse/` | Open-source decompiler, headless, Ghidra MCP |
| Go/Rust Reverse | `skills/go-rust-reverse/` | Stripped Go/Rust, pclntab, panic strings |
| Hardware Security | `skills/hardware-security/` | UART/JTAG/SWD, read-only extraction |
| IDA Pro Reverse | `skills/ida-reverse/` | 72-tool MCP: decompile, disasm, dataflow, xrefs |
| LLM/AI Security | `skills/llm-security/` | OWASP LLM Top 10: prompt injection, agent hijacking |
| Malware Analysis | `skills/malware-analysis/` | 6-stage analysis, YARA/Sigma, sandbox orchestration |
| Mobile Reverse | `skills/mobile-reverse/` | Android/iOS Frida/Objection, SSL pinning bypass |
| N-day Patch Diff | `skills/patch-diff-exploit/` | Vendor patch diffing, PoC development, weaponization |
| Penetration Tools | `skills/pentest-tools/` | Nmap/Nuclei/SQLMap/FFUF/Hashcat via MCP |
| Protocol Reverse | `skills/protocol-reverse/` | Custom binary protocols, Protobuf, gRPC, PCAP |
| Reverse Engineering | `skills/reverse-engineering/` | GDB/Frida/angr/Unicorn/Qiling, CTF patterns |
| Radare2 Analysis | `skills/radare2/` | CLI binary recon, disasm, patch: r2/rabin2/rasm2 |
| RE→Exploit Chain | `skills/pwn-chain/` | Stack/heap/kernel pwn, pwntools, libc-database |
| Supply Chain Security | `skills/supply-chain-security/` | SBOM/SCA/CI-CD: dependency scanning, container security |
| Threat Hunting | `skills/threat-hunting/` | Hypothesis-driven, Sigma detection, blue team |
| Threat Intelligence | `skills/threat-intelligence/` | Public IOC, activity correlation, independent verification |
| Windows/AD Security | `skills/windows-ad/` | Kerberos, AD CS, BloodHound, relay, domain paths |

## Routing & Authorization

**Critical:** All security tasks must pass through the authorization gate:
1. Run router: `powershell -NoProfile -ExecutionPolicy Bypass -File D:\drishti\tools\reverse-skill\scripts\master-route.ps1 -Hint "<task>"`
2. Initialize case: `powershell -File D:\drishti\tools\reverse-skill\scripts\case-init.ps1 -Hint "<task>"`
3. Check `work/<case>/scope.md` for `auth.status=granted` before ACT phase

## Tool Bootstrap

Missing tools are bootstrapped via:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\drishti\tools\reverse-skill\scripts\bootstrap-reverse.ps1 -Capability @('tool_name') -StartServices
```

Supported capabilities: jadx, apktool, jeb-pro, binaryninja, frida, frida-ps, idalib-mcp, reqable-mcp, jshookmcp, xquik-mcp, anything-analyzer, idapro, r2, rabin2, adb, agent-browser, ghidra-mcp, seclists, proxycat, burpsuite-mcp, nmap, pentestswarm, binwalk, yara, pwntools, bkcrack

## Usage in DRISHTI

This skill is activated for:
- Vulnerability scanner integration and validation
- Security finding correlation and analysis
- Penetration testing workflow orchestration
- Malware and binary analysis
- Authorized penetration testing execution
- Evidence-backed finding generation