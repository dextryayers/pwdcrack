# Phase 10 status: web dashboard (B-30)

What this file is: the honest state of `engines/engine-web` and the `web`
subcommand, with numbers from the last run and nothing estimated.

## The defect

`WebConfig::default()` returned `host: "0.0.0.0"` with `auth_token: None`. The
dashboard listened on every interface of every machine it ran on, with no
authentication, and any process that could reach the port could start an attack.

It also did not run attacks. `start_attack` set `status = Running`, wrote
"Attack started" to a log buffer, and returned success. Nothing was enqueued,
nothing was hashed. `stop`, `pause` and `resume` mutated the same enum.

That second half matters more than the first. A reachable port that does
nothing is an inconvenience. A dashboard reporting a running attack that is not
running tells an operator a job is in progress when it is not.

## Sub-phase results

| Task | State | Evidence |
|------|-------|----------|
| P10.1.01 loopback by default | **done, verified** | `WebConfig::default().host == "127.0.0.1"`; a test asserts it; running `pwdcrack web --web-host 0.0.0.0` exits 1 with a message naming the flag |
| P10.1.02 token, 0600, Bearer on mutations | **done, verified** | `scripts` integration test drives a real socket; `stat` on a generated token shows mode 600 |
| P10.1.03 CSRF | **done, verified** | a request with a valid token and no `X-Pwdcrack-Request` header is refused with 400 |
| P10.1.04 real attack execution | **done, verified** | a dictionary attack through the HTTP API recovered MD5("pwdcrack-reference-candidate"); the counters reported are the run's own |
| P10.1.05 rate limit and audit log | **done, verified** | 60 authorised requests at 10/s with a burst of 20 produce 429s, and the refusals are on `/api/audit` |
| P10.1.06 CSP forbidding inline script | **done, verified** | every response carries the policy; tests assert the served pages do not use what it forbids |
| P10.1.07 the 401 gate | **done, verified** | `an_unauthenticated_post_to_start_returns_401` drives a real TCP connection |

## Verified by running the binary

```
$ pwdcrack web --web-host 0.0.0.0 --web-token-file /tmp/t
[!] dashboard stopped: refusing to bind 0.0.0.0: it is reachable from outside this machine.
Pass --allow-exposed-web-bind to do it anyway, and read what that
means in docs/PHASE10_STATUS.md first.
exit 1

$ pwdcrack web --web-port 8094 --web-token-file /tmp/t
  address   127.0.0.1
  exposed   false
  dashboard token (shown once): <64 hex characters>
```

Against a running instance:

```
POST /api/start, no token          -> 401
POST /api/start, token, no header  -> 400
POST /api/start, token + header    -> {"success":true,"message":"attack started"}

GET /api/status after a real dictionary attack:
  status    Finished
  tested    1
  cracked   1
  hits      [{"hash": "8350c7ecc6d4706e12107df747eb6e71",
              "password": "pwdcrack-reference-candidate"}]
```

## How the real execution is wired

`engine-web` cannot call the engine. `pwdcrack` depends on it, so the reverse
edge is a dependency cycle and cargo rejects it outright. Adding the dependency
to prove it produced:

```
error: cyclic package dependency: package `pwdcrack v1.2.0` depends on itself
```

The seam is `engine_web::attack::AttackExecutor`, implemented by the binary in
`src/webexec.rs`. With that linked in, `POST /api/start` hashes things. Without
it, the route answers 503 and `/api/status` reports `executor_wired: false`. There
is no third state where a click produces success and no work.

`EngineExecutor` uses `Mask::candidate_string` for brute force, which maps an
index to a candidate directly, so a batch at offset N needs nothing generated
before it. For a dictionary it indexes the file once, eight bytes per line, then
seeks to the batch it was asked for. A ten million line wordlist is 80 MB of
index rather than gigabytes of words.

## What status means now

There is no stored status field. `AppState::status` derives what to report from
the live `AttackHandle`: a recorded executor failure first, then completion,
then pause, then running. There is nothing to set, so there is nothing that can
disagree with reality.

## Defects found while doing this

**The rate limiter never refused anything.** `refill_per_milli` was set to
`per_second * 1000`, which at 10 per second refilled ten thousand tokens every
millisecond. A token bucket with that refill is not a limiter. The unit tests
passed because they froze the clock and checked relative behaviour; the HTTP test
flooding the endpoint is what found it.

**A finished attack reported itself as running.** The batch loop returned
`StopReason::Completed` without touching the control flags, so the dashboard
showed `Running` forever with counters frozen. Every exit now goes through
`Control::conclude`.

**An executor failure was swallowed.** A failed batch returned
`StopReason::Stopped` and nothing recorded why, which left the status reading
`Running` with `tested: 0`. The reason is now stored and surfaced as
`AttackStatus::Error`, with the executor's own message.

**Dropping a handle left a control claiming Running.** `Drop` aborted the task
but did not set the stop flag, so anyone holding a clone of the control was told
an attack was in progress when its task was already dead.

**Pausing a finished attack returned 200.** The message was technically true and
the status was misleading. Pause and resume now answer 409 for a concluded run.

**`Form` cannot hold a `Vec`.** `Option<Vec<String>>` for `target_hashes` fails
with "invalid type: string, expected a sequence" on every request. It is one text
field, split on whitespace and commas, which also matches how the CLI reads a
hash file.

**The startup banner reported exposure backwards.** It printed whether the
operator had passed the flag, not whether the socket was reachable, so an
explicitly allowed `0.0.0.0` displayed `exposed false`.

**Three versions of one library.** `pwdcrack` was 1.2.0, `engine-bridge` said
0.1.0, and `BRIDGE_VERSION` said 1.1.0. Found while wiring the Python bridge and
fixed in `pwdcrack::VERSION`.

## Not done, stated plainly

**No TLS.** The token is a bearer credential, not encryption. On an exposed bind
it goes over the wire in clear. There is no `tokio-rustls` dependency and no
certificate handling, so the dashboard must stay on loopback or behind something
that terminates TLS. This is a real limitation, not a future plan.

**Read-only routes are unauthenticated.** `/api/status`, `/api/log`, `/api/audit`
and the websocket need no token. On the loopback default nothing else can reach
them, which is the case the default exists for. On an exposed bind they report
counters, the status, and cracked hashes and passwords. That is the same data
`/api/status` already returns, so token-gating them would not change what an
attacker with a token can see, only what one without it can see. If that trade is
wrong for a deployment, the answer is to leave the listener on loopback.

**No `Secure` cookie flag.** The cookie is `HttpOnly; SameSite=Strict` with no
`Secure`, because there is no TLS listener to make it meaningful. Adding it
without TLS would stop the dashboard working on plain HTTP, which is the only
mode it has.

**One attack at a time.** `POST /api/start` while an attack runs stops the old
one and starts the new. There is no queue and no per-session isolation in the
web surface. `AttackHandle` is one handle; multiple concurrent attacks would
need a different state shape.

**No combinator attack.** `AttackRequest::validate` refuses it with a message
saying it is not wired, rather than silently running nothing.

## Files

```
engines/engine-web/src/auth.rs       bind policy, token store, CSRF, rate limit, audit, CSP
engines/engine-web/src/attack.rs     AttackExecutor trait, AttackHandle, Control, the batch loop
engines/engine-web/src/server.rs     AppState, derived status, serve and serve_on
engines/engine-web/src/routes.rs     the guard, the routes, CSP compliant pages
engines/engine-web/src/websocket.rs  the status stream
engines/engine-web/tests/dashboard_gate.rs   21 tests over real sockets
src/webexec.rs                       the executor, calling the real engine
src/main.rs                          cmd_web
scripts/gen-rtl-vectors.py           unrelated, see PHASE8_STATUS.md
```