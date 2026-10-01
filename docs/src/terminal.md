# `ttk-terminal` Architecture

Crate reference for `../../crates/terminal`. For the system-level picture (attestation, onion routing, vsock, deployment), see the [workspace ARCHITECTURE.md](../../docs/src/ARCHITECTURE.md).

Other crates: [`ttk-core`](core.md) · [`ttk-client`](client.md) · [`ttk-relay`](relay.md)

> **Role:** an attested node that is always the **last hop**. It never forwards, and it is the only node that can decrypt the message.

## 1. Files

| File | Responsibility |
|---|---|
| `../../crates/terminal/src/lib.rs` | `Terminal`, `run()`, `/faf` handler |
| `../../crates/terminal/src/main.rs` | `terminal` binary: `env_logger::init()` + `ttk_terminal::run()` |

## 2. Public API

| Item | Kind | Description |
|---|---|---|
| `run()` | async fn | `Terminal::new(Server::listen(Listener::from_env()?))` then serve |
| `Terminal::new(server)` | fn | Wrap a core `Server` |
| `Terminal::bind(addr)` | fn | Attest and bind UDP |
| `Terminal::local_addr()` / `serve()` | fn | Bound address; serve base routes + `POST /faf` |

## 3. `POST /faf` handler

```mermaid
flowchart LR
    A["FafRequest"] --> B{"relays empty?"}
    B -- no --> E1["400 relays left"]
    B -- yes --> C["open_body(node_key)"]
    C -- fail --> E2["400 invalid body"]
    C -- ok --> D["log message (UTF-8)"] --> OK["200 delivered"]
```

| Status | When |
|---|---|
| `200 delivered` | Body decrypted |
| `400` | Relays still present, or body can't be decrypted |
| `413` | Body > 1 MiB (core) |

The handler never logs the key. In this version it logs the decrypted message at `info` level.

## 4. Configuration, features and tests

| Variable | Default | Effect |
|---|---|---|
| `TTK_USE_UDP` / `TTK_LISTEN_ADDR` / `TTK_VSOCK_PORT` | vsock `5000` | Listener |
| `TTK_ATTESTATION` | auto-detect | Force a provider (core) |

Features forward to `ttk-core` (as for the relay). It makes no outbound connections, so it has no transport or verifier settings.

| File | Covers |
|---|---|
| `../../crates/terminal/tests/terminal_tests.rs` | Delivery, relays-left rejection, undecryptable body |
