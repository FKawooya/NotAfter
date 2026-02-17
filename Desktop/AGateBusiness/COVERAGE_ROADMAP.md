# AgentGate — Coverage Roadmap

> Derived from validation of 42 real-world agent use cases against AgentGate capabilities.
> Last updated: 2026-02-17

---

## Executive Summary

AgentGate v1.0 provides **network-layer governance** — identity, capability enforcement, audit, and revocation for all agent HTTP traffic. This covers **32 of 42 validated use cases fully** (76%) with the remaining 10 having partial coverage.

The gap: **host-level operations** — file system access, shell execution, hardware interaction, and IDE integration are invisible to the forward proxy.

This roadmap closes that gap across four tiers, reaching **100% coverage** by v2.0.

---

## Current Gap Analysis

### The 10 Partial Cases

| # | Use Case | Category | Missing Governance |
|---|----------|----------|--------------------|
| 1 | Running shell commands and manipulating local files | OpenClaw | `shell:execute`, `fs:read`, `fs:write` |
| 2 | Taking photos based on conditional triggers | OpenClaw | `hardware:camera` |
| 3 | Managing Claude Code or Codex coding sessions | OpenClaw | `process:spawn`, `ai:invoke` (semantic) |
| 4 | Building simple web apps from a phone | OpenClaw | `fs:write`, `deploy:write` |
| 5 | Complex multi-file code refactoring | Coding | `fs:read`, `fs:write`, `git:commit` |
| 6 | Automated git commit generation | Coding | `git:commit`, `git:push` |
| 7 | Codebase auditing and improvement | Coding | `fs:read`, `ai:invoke` |
| 8 | Building a C compiler autonomously | Coding | `shell:execute`, `fs:write`, `process:spawn` |
| 9 | Agentic coding inside Xcode | Coding | `ide:edit`, `ide:build` |
| 10 | Data analysis tasks (regression, clustering, etc.) | Multi-Agent | `fs:read`, `data:process` |

### Root Cause

All 10 cases share one trait: **local compute** that doesn't traverse the network proxy. AgentGate sees the agent's outbound HTTP traffic but is blind to what happens on the host.

---

## New Capability Types

Extending the capability model beyond HTTP verbs to a full agent permission system.

### Tier 1 Capabilities (SDK-enforced)

| Capability | Description | Operations |
|------------|-------------|------------|
| `fs:read` | File system read access | Read file contents, list directories, stat files |
| `fs:write` | File system write access | Create, modify, delete files and directories |
| `shell:execute` | Shell command execution | Run commands, capture output, set environment |
| `git:commit` | Git commit creation | Stage files, create commits |
| `git:push` | Git push to remotes | Push branches, create tags |
| `ai:invoke` | LLM/AI API invocation | Semantic marker for AI-to-AI calls (HTTP-level already governed) |

### Tier 2 Capabilities (Runtime-enforced)

| Capability | Description | Enforcement |
|------------|-------------|-------------|
| `process:spawn` | Child process creation | cgroup/namespace limits |
| `fs:path:<glob>` | Path-scoped file access | FUSE mount or seccomp filter |
| `shell:command:<pattern>` | Command-scoped execution | Allowlist/denylist matching |
| `resource:cpu:<limit>` | CPU resource cap | cgroup limits |
| `resource:memory:<limit>` | Memory resource cap | cgroup limits |

### Tier 3 Capabilities (Kernel-enforced)

| Capability | Description | Enforcement |
|------------|-------------|-------------|
| `hardware:camera` | Camera/imaging device access | ioctl monitoring via eBPF |
| `hardware:sensor` | Sensor/peripheral access | Device file monitoring |
| `network:direct` | Non-proxy network access | Socket connect monitoring |
| `ide:edit` | IDE file modification | Process tree monitoring |
| `ide:build` | IDE build triggering | execve monitoring |

---

## Tier 1: SDK Local Operations (v1.1)

**Effort:** 2-3 weeks | **Coverage impact:** 76% → 90%

### Design Principles

1. **Same passport, expanded capabilities** — No new auth mechanism. The existing JWT passport carries the new capability strings.
2. **Audit-first** — Every local operation logs to the existing audit service `/log` endpoint before executing.
3. **Policy-checked** — The SDK validates the agent's passport capabilities locally before allowing the operation.
4. **Voluntary adoption** — Agents must use the SDK. This targets the "good actor seeking governance" market.

### Architecture

```
Agent Code
    │
    ▼
AgentGate SDK (local ops module)
    │
    ├── 1. Check passport has required capability (local JWT inspection)
    ├── 2. Check operation against local policy rules (path/command allowlists)
    ├── 3. Log operation to audit service (POST /log with operation details)
    └── 4. Execute the operation (fs/shell/git)
            │
            ▼
        Local OS (file system, shell, git)
```

### SDK Interface Specification

#### Python SDK (`agentgate.local`)

```python
from agentgate import AgentGateClient, ProxyClient
from agentgate.local import LocalOpsClient

async with LocalOpsClient(
    audit_url="https://localhost:8081",
    passport_provider=get_passport,
    policy_path="/etc/agentgate/host-policy.json",  # optional
) as local:
    # File operations — requires fs:read / fs:write capability
    content = await local.fs_read("/app/data/input.csv")
    await local.fs_write("/app/output/result.json", json_data)
    entries = await local.fs_list("/app/data/")

    # Shell execution — requires shell:execute capability
    result = await local.shell_exec("pytest tests/ -v", timeout=60)
    # result.stdout, result.stderr, result.exit_code

    # Git operations — requires git:commit / git:push capability
    await local.git_commit(
        repo_path="/app",
        message="fix: resolve auth bug",
        files=["src/auth.py", "tests/test_auth.py"],
    )
    await local.git_push(repo_path="/app", remote="origin", branch="main")
```

#### TypeScript SDK (`agentgate/local`)

```typescript
import { LocalOpsClient } from 'agentgate/local';

const local = new LocalOpsClient({
  auditUrl: 'https://localhost:8081',
  getPassport: () => passport,
});

// File operations
const content = await local.fsRead('/app/data/input.csv');
await local.fsWrite('/app/output/result.json', jsonData);

// Shell execution
const result = await local.shellExec('npm test', { timeout: 60000 });

// Git operations
await local.gitCommit({
  repoPath: '/app',
  message: 'fix: resolve auth bug',
  files: ['src/auth.ts'],
});
```

#### Go SDK (`agents/shared/localops`)

```go
import "github.com/agentgate/agents/shared/localops"

client := localops.New(localops.Config{
    AuditURL:    "https://localhost:8081",
    GetPassport: getPassportFunc,
    PolicyPath:  "/etc/agentgate/host-policy.json",
})

// File operations
content, err := client.FSRead(ctx, "/app/data/input.csv")
err = client.FSWrite(ctx, "/app/output/result.json", data)

// Shell execution
result, err := client.ShellExec(ctx, "go test ./...", localops.ExecOpts{Timeout: 60 * time.Second})

// Git operations
err = client.GitCommit(ctx, "/app", "fix: resolve auth bug", []string{"main.go"})
err = client.GitPush(ctx, "/app", "origin", "main")
```

### Audit Log Format (new operation types)

```json
{
  "timestamp": "2026-02-17T10:30:00Z",
  "agent_id": "netwatch-prod",
  "agent_type": "monitor",
  "owner": "ops@example.com",
  "operation": "fs:write",
  "details": {
    "path": "/app/output/report.json",
    "size_bytes": 4096,
    "action": "create"
  },
  "policy_decision": "allow",
  "matched_rule": "fs-app-write",
  "passport_id": "jti-abc123",
  "source_ip": "10.1.10.98"
}
```

```json
{
  "timestamp": "2026-02-17T10:30:05Z",
  "agent_id": "coder-agent",
  "operation": "shell:execute",
  "details": {
    "command": "pytest tests/ -v",
    "exit_code": 0,
    "duration_ms": 3200,
    "stdout_lines": 42,
    "stderr_lines": 0
  },
  "policy_decision": "allow",
  "matched_rule": "shell-test-commands"
}
```

### Host Policy Schema

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "fs-app-read",
      "capability": "fs:read",
      "allow_paths": ["/app/**", "/data/**", "/tmp/agentgate-*"],
      "deny_paths": ["/etc/shadow", "/root/**", "**/.env", "**/*secret*"]
    },
    {
      "id": "fs-app-write",
      "capability": "fs:write",
      "allow_paths": ["/app/output/**", "/tmp/agentgate-*"],
      "deny_paths": ["/app/config/**", "/etc/**"]
    },
    {
      "id": "shell-safe-commands",
      "capability": "shell:execute",
      "allow_commands": ["pytest", "npm test", "go test", "make", "eslint"],
      "deny_commands": ["rm -rf", "curl", "wget", "ssh", "sudo"],
      "max_timeout_seconds": 300
    },
    {
      "id": "git-standard",
      "capability": "git:commit",
      "allow_branches": ["feature/*", "fix/*"],
      "deny_branches": ["main", "master", "release/*"],
      "require_signed": false
    },
    {
      "id": "git-push-standard",
      "capability": "git:push",
      "allow_remotes": ["origin"],
      "deny_force_push": true
    }
  ]
}
```

### Cases Closed by Tier 1

| # | Use Case | Before | After | How |
|---|----------|:------:|:-----:|-----|
| 4 | Building simple web apps | Partial | **Full** | `fs:write` governs file creation; deploy via HTTP already governed |
| 5 | Complex multi-file code refactoring | Partial | **Full** | `fs:read` + `fs:write` governs all file operations |
| 6 | Automated git commit generation | Partial | **Full** | `git:commit` + `git:push` governs the full git workflow |
| 7 | Codebase auditing and improvement | Partial | **Full** | `fs:read` + `ai:invoke` governs read access + AI calls |
| 10 | Data analysis tasks | Partial | **Full** | `fs:read` governs dataset access; `fs:write` governs output |
| 15 | Running automated tests (was full-ish) | Full | **Full+** | `shell:execute` adds visibility into test execution |

---

## Tier 1.5: Git/CI Integration (v1.1)

**Effort:** 1 week | **Coverage impact:** Strengthens coding agent cases

### Components

#### 1. Pre-commit Hook (`scripts/hooks/pre-commit`)

```bash
#!/bin/sh
# AgentGate pre-commit hook
# Validates that the committing process has a valid passport with git:commit capability

PASSPORT_FILE="${AGENTGATE_PASSPORT_FILE:-/var/lib/agentgate/agent.json}"

if [ -f "$PASSPORT_FILE" ]; then
    # Agent is running under AgentGate — validate passport
    agctl verify-passport \
        --passport-file "$PASSPORT_FILE" \
        --require-capability git:commit \
        --audit-url "${AGENTGATE_AUDIT_URL}" \
        || { echo "AgentGate: passport validation failed — commit blocked"; exit 1; }
fi
# If no passport file, allow (human developer)
```

#### 2. GitHub Actions Reusable Workflow (`.github/workflows/verify-agent.yml`)

```yaml
name: Verify Agent Identity
on:
  workflow_call:
    inputs:
      require-capability:
        required: true
        type: string

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Check agent passport
        run: |
          COMMIT_AUTHOR=$(git log -1 --format='%ae')
          if echo "$COMMIT_AUTHOR" | grep -q "@agentgate"; then
            agctl verify-agent "$COMMIT_AUTHOR" --capability "${{ inputs.require-capability }}"
          fi
```

#### 3. PR Agent Identity Badge

Agents that create PRs include a standardized identity block:

```markdown
---
**Agent Identity**
| Field | Value |
|-------|-------|
| Agent | `coder-agent-v1.2` |
| Passport | Valid (expires 2026-03-01) |
| Capabilities | `fs:read`, `fs:write`, `git:commit`, `git:push`, `ai:invoke` |
| Operations | 47 file modifications, 3 shell executions, 12 AI invocations |
| Audit Trail | [View in ACC](https://acc.example.com/agents/coder-agent/audit) |
---
```

---

## Tier 2: Agent Runtime Wrapper (v1.2)

**Effort:** 4-6 weeks | **Coverage impact:** 90% → 95%

### Overview

`agentgate-run` is a CLI tool that launches any agent process under OS-level governance. No SDK integration required — works with any binary, script, or container.

### Architecture

```
$ agentgate-run --passport agent.json --policy host-policy.json -- python agent.py

┌─────────────────────────────────────────────────────────────┐
│                    agentgate-run (supervisor)                │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Namespace     │  │ Seccomp/     │  │ Audit Reporter   │  │
│  │ Manager       │  │ AppArmor     │  │ (→ audit svc)    │  │
│  │               │  │ Filter       │  │                  │  │
│  │ - mount ns    │  │ - file ACLs  │  │ - fs events      │  │
│  │ - pid ns      │  │ - syscall    │  │ - exec events    │  │
│  │ - net ns      │  │   allowlist  │  │ - net events     │  │
│  │ - cgroup      │  │ - path rules │  │ - resource usage │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │             │
│         └────────┬────────┘                    │             │
│                  ▼                             │             │
│         ┌────────────────┐                     │             │
│         │  Agent Process  │ ──── events ───────┘             │
│         │  (sandboxed)    │                                  │
│         └────────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```

### CLI Interface

```bash
# Basic usage — launch agent with passport governance
agentgate-run \
    --passport /var/lib/agentgate/myagent.json \
    --policy /etc/agentgate/host-policy.json \
    --audit-url https://localhost:8081 \
    -- python my_agent.py --config /app/config.yaml

# With resource limits
agentgate-run \
    --passport agent.json \
    --policy policy.json \
    --max-cpu 2 \
    --max-memory 1G \
    --max-pids 50 \
    --network-mode proxy-only \
    -- ./my-agent

# Dry run (audit mode — log everything, enforce nothing)
agentgate-run \
    --passport agent.json \
    --policy policy.json \
    --mode audit \
    -- ./my-agent
```

### Enforcement Mechanisms

| Mechanism | Platform | What It Controls |
|-----------|----------|------------------|
| Mount namespace | Linux | Restrict visible filesystem paths |
| PID namespace | Linux | Isolate process tree |
| Network namespace | Linux | Force traffic through proxy (no direct connections) |
| cgroups v2 | Linux | CPU, memory, PID limits |
| Seccomp-BPF | Linux | Syscall filtering (block dangerous syscalls) |
| AppArmor/SELinux | Linux | MAC-level file and network ACLs |
| Job Objects | Windows | Process tree limits, memory caps |

### Cases Closed by Tier 2

| # | Use Case | Before | After | How |
|---|----------|:------:|:-----:|-----|
| 1 | Running shell commands + local files | Partial | **Full** | Process sandboxed, all file/exec operations logged |
| 8 | Building a C compiler autonomously | Partial | **Full** | `process:spawn` limited, file writes confined to output dir |
| 3 | Managing coding sessions | Partial | **Full** | Process tree monitoring shows all subprocess activity |

---

## Tier 3: eBPF Observer (v2.0)

**Effort:** 8-12 weeks | **Coverage impact:** 95% → 100%

### Overview

Kernel-level agent activity monitor. Zero agent cooperation required. Monitors all syscalls from identified agent processes.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Linux Kernel                      │
│                                                          │
│   ┌──────────────────────────────────────────────────┐   │
│   │                eBPF Probes                        │   │
│   │                                                   │   │
│   │   tracepoint/syscalls/sys_enter_openat ──┐        │   │
│   │   tracepoint/syscalls/sys_enter_execve ──┤        │   │
│   │   tracepoint/syscalls/sys_enter_connect ─┤ ring   │   │
│   │   tracepoint/syscalls/sys_enter_ioctl ───┤ buffer │   │
│   │   tracepoint/sched/sched_process_fork ───┘        │   │
│   │                                                   │   │
│   └──────────────────────┬───────────────────────────┘   │
│                          │                               │
└──────────────────────────┼───────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  agentgate-observer    │
              │  (userspace daemon)    │
              │                        │
              │  - PID → Agent mapping │
              │  - Event filtering     │
              │  - Policy evaluation   │
              │  - Batch audit upload  │
              └───────────┬────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │  Audit Service (/log)  │
              └────────────────────────┘
```

### eBPF Probe Points

| Probe | Syscall | Data Captured | Use |
|-------|---------|---------------|-----|
| `sys_enter_openat` | File open | pid, path, flags (R/W/RW) | `fs:read`, `fs:write` detection |
| `sys_enter_execve` | Process exec | pid, binary path, argv | `shell:execute`, `process:spawn` |
| `sys_enter_connect` | Network connect | pid, addr, port, protocol | Proxy bypass detection |
| `sys_enter_ioctl` | Device control | pid, device fd, request code | `hardware:camera`, `hardware:sensor` |
| `sched_process_fork` | Process creation | parent pid, child pid | Process tree tracking |
| `sys_enter_write` | Write (filtered) | pid, fd, size (for device fds only) | Hardware data exfiltration |

### Agent Process Identification

The observer needs to know which PIDs are agent processes:

1. **cgroup-based** (preferred) — Agent processes launched in `/sys/fs/cgroup/agentgate/<agent-id>/`. Observer watches this cgroup hierarchy.
2. **PID file registration** — `agentgate-run` writes PID to `/run/agentgate/<agent-id>.pid`. Observer watches this directory.
3. **Process environment** — Agents set `AGENTGATE_AGENT_ID=<id>` in environment. Observer reads `/proc/<pid>/environ`.
4. **Container label** — For containerized agents, read container labels via CRI API.

### Cases Closed by Tier 3

| # | Use Case | Before | After | How |
|---|----------|:------:|:-----:|-----|
| 2 | Taking photos (conditional triggers) | Partial | **Full** | `ioctl` monitoring on camera device fd |
| 9 | Agentic coding inside Xcode | Partial | **Full** | `execve` monitoring shows Xcode subprocess activity |

---

## Coverage Progression

| Metric | v1.0 (now) | v1.1 (+Tier 1/1.5) | v1.2 (+Tier 2) | v2.0 (+Tier 3) |
|--------|:----------:|:-------------------:|:--------------:|:--------------:|
| Full coverage | 32/42 (76%) | 38/42 (90%) | 40/42 (95%) | 42/42 (100%) |
| Partial | 10/42 | 4/42 | 2/42 | 0/42 |
| Enforcement model | Network proxy | Proxy + SDK | Proxy + SDK + OS | Proxy + SDK + OS + Kernel |
| Agent cooperation required | Yes (use proxy) | Yes (use SDK) | No (wrapper) | No (kernel) |

---

## Implementation Plan

### Phase 1: Foundation (Week 1)

| Task | Owner | Deliverable |
|------|-------|-------------|
| Define audit log schema for new ops | Audit Agent | Updated `app/models.py`, `/log` endpoint accepts new types |
| Define host policy JSON schema | Policy Agent | `host-policy.schema.json` + example policy |
| Update policy engine for new capabilities | Policy Agent | `internal/policy/policy.go` extended |

### Phase 2: SDK Implementation (Weeks 2-3)

| Task | Owner | Deliverable |
|------|-------|-------------|
| Python SDK `agentgate.local` module | Python Agent | `src/agentgate/local.py` + tests |
| TypeScript SDK `agentgate/local` module | TypeScript Agent | `src/local.ts` + tests |
| Go SDK `localops` package | Go Agent | `agents/shared/localops/` + tests |
| Git hooks + CI workflow | Git/CI Agent | `scripts/hooks/`, `.github/workflows/verify-agent.yml` |

### Phase 3: Runtime Wrapper (Weeks 4-9)

| Task | Owner | Deliverable |
|------|-------|-------------|
| `agentgate-run` CLI scaffold | Runtime Agent | `runtime/cmd/agentgate-run/` |
| Namespace/cgroup manager | Runtime Agent | `runtime/internal/sandbox/` |
| Seccomp filter loader | Runtime Agent | `runtime/internal/seccomp/` |
| Event reporter (→ audit service) | Runtime Agent | `runtime/internal/reporter/` |

### Phase 4: eBPF Observer (Weeks 10-20)

| Task | Owner | Deliverable |
|------|-------|-------------|
| eBPF probe programs (C) | eBPF Agent | `observer/bpf/` |
| Userspace daemon (Go) | eBPF Agent | `observer/cmd/agentgate-observer/` |
| PID→Agent mapping | eBPF Agent | `observer/internal/procmap/` |
| Policy evaluation engine | eBPF Agent | `observer/internal/policy/` |

---

## Testing Strategy

### Tier 1 Testing

- **Unit tests**: Each SDK operation tested with mock audit service (respx/nock/httptest)
- **Integration tests**: SDK → real audit service, verify logs appear with correct operation types
- **Policy tests**: Verify allow/deny decisions for path globs, command patterns, branch restrictions
- **Negative tests**: Verify operations fail when passport lacks required capability

### Tier 2 Testing

- **Sandbox escape tests**: Verify agent cannot access files outside allowed paths
- **Process limit tests**: Verify cgroup PID/memory/CPU enforcement
- **Network isolation tests**: Verify agent cannot make direct connections (must use proxy)
- **Audit completeness tests**: Verify all file/exec/net operations appear in audit log

### Tier 3 Testing

- **Probe accuracy tests**: Verify eBPF captures all target syscalls with correct data
- **Performance tests**: Measure overhead of eBPF probes on normal workloads (target: <1% CPU)
- **PID mapping tests**: Verify correct agent attribution across fork/exec chains
- **Proxy bypass detection tests**: Verify direct network connections are detected and reported

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Use case coverage | 100% (42/42) | Validated against field use case inventory |
| SDK adoption friction | <10 min integration | Time from `pip install` to first governed local op |
| Audit completeness | 100% of governed ops logged | No governed operation executes without audit entry |
| Policy enforcement accuracy | 0 false allows, <1% false denies | Fuzz testing with randomized operations |
| Performance overhead (SDK) | <5ms per operation | Benchmark: governed vs ungoverned file read |
| Performance overhead (eBPF) | <1% CPU | Benchmark: agent workload with/without observer |
