# /security-audit Command

Execute a coordinated security review with Security Auditor, Backend Engineer, and QA Reviewer.

## Usage
```
/security-audit [target]
```

## Behavior

1. **Scope Definition** - Define audit scope (target: scanner, API, auth, database, infrastructure)
2. **Skill Selection** - Load reverse-skill (code-audit, api-security, supply-chain-security) and ecc/security-review
3. **Agent Delegation**:
   - Security Auditor: Lead review, identify vulnerabilities
   - Backend Engineer: Review implementation code
   - QA Reviewer: Validate security tests exist
4. **Review Areas**:
   - Authorization enforcement
   - SSRF/redirect protection
   - XML external entity rejection
   - Subprocess timeout/cleanup
   - RLS policies
   - Secret handling
   - Scanner input validation
5. **Reporting**: Structured findings with severity, evidence, remediation

## Target Options
- `scanners` - All scanner adapters
- `api` - API endpoints and contracts
- `auth` - Authorization and DNS TXT
- `database` - Schema, RLS, migrations
- `infrastructure` - Docker, containers, secrets
- `all` - Complete audit

## Example
```
/security-audit scanners
/security-audit auth
/security-audit all
```

## Output
Structured security audit report with:
- Findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Evidence and reproduction steps
- Remediation recommendations
- Test coverage gaps