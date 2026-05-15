# Relay replay-proxy harness (W7.1)

This package owns the localhost mitmproxy harness that
`rly replay run --proxy` spawns to serve cassette responses to an agent
subprocess.

## Surface

- `HarnessSession.start()` — generate per-session CA, allocate a free
  ephemeral port on `127.0.0.1`, spawn the proxy driver, wait for it to
  be ready, return a `HarnessHandle`.
- `HarnessSession.agent_env(parent_env=...)` — produce the `dict[str, str]`
  to pass to `subprocess.Popen(env=...)`. Sets `HTTPS_PROXY`,
  `HTTP_PROXY`, `SSL_CERT_FILE`, `RELAY_REPLAY_SESSION`,
  `RELAY_REPLAY_PROXY_URL` atomically.
- `HarnessSession.assert_alive()` — raise `RelayProxyDownError` if the
  driver exited or the proxy port no longer accepts TCP. Cheap; called
  by the SDK adapter shim before each request.
- `HarnessSession.stop()` — idempotent teardown; removes the per-session
  CA cert + key.

## Drivers

Pick via the `RELAY_REPLAY_PROXY_DRIVER` env var.

| Driver | Use | Cost |
| --- | --- | --- |
| `inproc` (default) | Plumbing-tier tests, Windows hosts without mitmproxy | Pure Python; no external dep |
| `mitmproxy` | Smoke-tier tests; full TLS-MITM | Requires `mitmdump` on PATH |
| `fake-failure` | VAL-W7-010 tier-1 plumbing path | Driver exits immediately |

## File layout per session

```text
${RELAY_HOME}/cassettes/<session_id>/
  ca.pem            # 0o644, ECDSA-P256 self-signed CA
  ca-key.pem        # 0o600, PKCS8 private key
  cassette.jsonl    # JSONL recorded by `rly replay record`
  _addon.py         # only when DRIVER=mitmproxy; auto-cleaned on stop()
```

Per VAL-W7-005 the harness writes nowhere else — no `/tmp` PEM, no system
trust store install. `SSL_CERT_FILE` injection is the only trust path.

## Cross-platform

The `inproc` driver is pure-Python `http.server.HTTPServer` and works on
macOS, Linux, and Windows without Docker or WSL2 (VAL-W7-014). The
`mitmproxy` driver is opt-in for hosts that have it.

Process termination is by PID only (`subprocess.Popen.terminate` /
`HTTPServer.shutdown`). Never by name; never by `pkill` / `killall`.
