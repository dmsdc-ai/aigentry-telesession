# telesession

telesession is the aigentry ecosystem remote session connection layer. It is an independent project with a one-way dependency on telepty.

## Ownership
- telesession: external client adapters (including MCP), remote connection/authentication, mailbox/queue/reconnect/deduplication, runtime and exact-session targeting.
- telepty: generic PTY identity, safe terminal delivery, outputs/events and delivery observations. It must run without telesession.
- orchestrator: task interpretation, approval state, execution/verification and progress/final reports.
- Do not couple transport to a named Dot, app, model or terminal UI. No invented task success from queue/receipt/output.

## Current task
Task1215, user authorization2026-10-09, handoff telesession-context-20261009-1202 plus later explicit implementation authorization. Target current personal Dot and existing orchestrator via telepty; other clients attach through adapters. Native macOS/Windows/Linux common Node path. Initial private GitHub source upload of this WIP snapshot was authorized on 2026-10-11; it is not a release and does not authorize npm publication. Remote runtime, remote service credentials, tunnel, deployment and live daemon restart are governed separately and are not authorized by this repository.

## Workflow
Controller uses aigentry-orchestrator task-bound dispatch helper with actual per-attempt confinement, visible native terminal surfaces, no forced submit, and independent verification. All worker communication uses scoped telepty; absent scoped sender must report TRANSPORT_BLOCKED and preserve artifacts. No raw unconstrained spawn, global permission grants or sender impersonation.

## Evidence
Source, tests, installed runtime and real Dot roundtrip are separate gates. Pending transport cannot be reported as completion. A local MCP stdio process does not establish a remote ChatGPT connection. Configuration and credentials are host-controlled and never tool parameters.
