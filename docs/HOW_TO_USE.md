# How to use Zlint

Zlint checks a shielded spend and prints yes, no, or warn, with a reason. It reads a policy file, a JSON activity window, and either a JSON spend proposal or a partially built transaction.

Advice commands do not sign. Enforce commands hold FROST share 2 and return one commitment or one signature share. Zlint does not talk to a wallet, a node, or the chain, and it does not broadcast.

Amounts are zatoshis. 1 ZEC is `100_000_000`.

Commands below use `cargo run -p zlint-cli --` from this repository. After `cargo build -p zlint-cli`, the same flags work on `target/debug/zlint`.

## What each command does

| Command | Signs? | Writes SQLite? |
|---------|--------|----------------|
| `policy show` | no | no |
| `decide` | no | only with `--db`. An accept is counted immediately |
| `review` | no | no |
| `history` | no | reads the log |
| `mcp` (`propose_spend`, `review_pczt`) | no | no |
| `share init` | no. Writes a simulated share file, mode 0600 | no |
| `cosign` | simulated share on accept, or on a warning after `confirm`. Refuses a FROST share | an accept is counted only when a share is written |
| `serve` / `propose` | same simulated share, over a Unix socket. `propose` does not open a share file | the server writes it |
| `confirm` | simulated: a dummy share. FROST: records the confirmation and prints `signature_share: null` | pending and confirmed warning rows |
| `frost keygen` | no. Writes share 1 and share 2, mode 0600. Trusted dealer | no |
| `frost prepare` | no. Prints share 1's public commitment. The nonce file stays | no |
| `frost serve` | listens for `commit` and `sign`. Share 2 stays in the process | pending warning, then an accept when a signature share is written |
| `frost commit` | asks the server for share 2's public commitment | the server may write a pending warning |
| `frost sign` | asks the server for share 2's signature share | the server counts the accept when the share is written |
| `frost contribute` | prints share 1's signature share and deletes that nonce file | no |
| `frost mcp` (`cosign_pczt`) | same round as `frost serve`. Confirm is not a tool | same as `frost serve` |

Accept, reject, and warn from `decide` and `review` exit 0. A missing file, bad JSON, unknown flag, or a co-signer refusal exits 2. `fail` prints `zlint: {reason}` on stderr. The JSON result goes to stdout. A short summary goes to stderr. Share files and nonce files are mode 0600. Responses do not include the share-file id or the secret nonce.

## Show a policy

```text
cargo run -p zlint-cli -- policy show --policy config/policy.example.yaml
```

`config/policy.example.yaml` is the product default: daily cap 2 ZEC, max transaction 0.5 ZEC, reject below 60, warn below 75, at most 5 accepted spends per hour, empty allowlist. `config/policy.demo.yaml` is tighter: daily cap 1 ZEC, reject below 70, warn below 85.

Score starts at 100. Each fired check subtracts its weight once. A hard-rule failure is a reject even if the score is still 100. Otherwise `score < reject_below` rejects, `score < warn_below` warns, and anything else accepts. A score equal to a threshold does not cross it.

Checks, in order: timing (40), round or distinctive amount (15), shield-after-receive (35), change/note selection (25). Hard rules, in order: max transaction, daily cap, allowlist, rate limit.

## Decide

Without `--db`, `decide` uses only the files you pass.

```text
cargo run -p zlint-cli -- decide \
  --policy config/policy.example.yaml \
  --activity fixtures/demo_activity.json \
  --proposal fixtures/proposals/clean_accept.json
```

| Proposal | Activity | Policy | Result |
|----------|----------|--------|--------|
| `fixtures/proposals/clean_accept.json` | `fixtures/demo_activity.json` | example | accept, score 100 |
| `fixtures/proposals/timing_reject.json` | `fixtures/demo_activity.json` | example | reject, score 45, timing and round flags |
| `fixtures/proposals/daily_cap_reject.json` | `fixtures/cap_activity.json` | demo | reject, score 100, `daily_cap` only |
| `fixtures/proposals/shield_warn.json` | `fixtures/demo_activity.json` | example | warn, score 65 |
| same shield proposal | same | demo | reject, because 65 is below 70 |

`--report PATH` writes the same JSON that stdout prints. If that write fails, the process exits 2 and does not print the decision.

The activity file is the history the linter sees (receives, shields, already-accepted spends). Zlint does not hold a viewing key and does not trial-decrypt. The caller supplies that window.

Optional proposal fields `input_zatoshis` and `change_zatoshis` turn on the change check. Both must be present and the input must be greater than 0. The flag `change_note_selection` fires when change/input is at least `change_fraction` (0.95 in the example policy). Missing either field skips the check.

`--db PATH` opens a local log. Accepted spends already in the activity file are kept, and rows in that database are added before the decision, so the cap and the rate limit see both. Every decision is logged. An accept is recorded once, and asking about the same proposal again does not count it twice. A warning is not an accepted spend. `history` reads this log.

## Check a transaction a wallet built

`zlint review` reads a PCZT, the partially built Zcash transaction a wallet or an agent already created. The shielded output that has an address is the payment. An output with an amount and no address is treated as change. You still pass the recent history, and `--at`, because the transaction file has no clock.

```text
cargo run -p zlint-cli -- review \
  --policy config/policy.example.yaml \
  --activity fixtures/demo_activity.json \
  --pczt payment.pczt \
  --at 1760003600000
```

Transparent payments are ignored. If the wallet hid an amount, Zlint stops instead of guessing. Stderr says `checked the transaction. does not sign.` A caller that still holds the full spend key can ignore the answer.

The MCP tool `review_pczt` asks the same question. It takes `policy_path`, `activity_path`, `pczt_path`, and `proposed_at_ms`. It does not sign and it does not write the log.

## Read the log

```text
cargo run -p zlint-cli -- history --db /tmp/zlint.db --limit 20
```

Newest first. Each line is `verdict  score N  proposed <ms>  <sha256 hex>`, then indented flag lines. An empty database prints `no decisions`. `--limit` defaults to 20.

## MCP advice

`zlint mcp` speaks newline-delimited JSON-RPC 2.0 on stdin and stdout. It echoes the client's `protocolVersion` (default `2024-11-05`). It handles `initialize`, `ping`, `tools/list`, and `tools/call`. Notifications (no `id`, or a method starting with `notifications/`) get no response.

The tools are `propose_spend` and `review_pczt`. Neither signs, and neither writes the decision log. `propose_spend` takes `policy_path`, `activity_path`, and either `proposal_path` or an inline `proposal` object. `review_pczt` takes `policy_path`, `activity_path`, `pczt_path`, and `proposed_at_ms`. The result is pretty decision JSON in an MCP text content block. `isError` is false on a decision and true when a path or field is missing. `confirm` returns an error saying confirm stays on this machine. `cosign_pczt` is not a tool on this server.

```text
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"propose_spend","arguments":{"policy_path":"config/policy.example.yaml","activity_path":"fixtures/demo_activity.json","proposal_path":"fixtures/proposals/timing_reject.json"}}}' \
  | cargo run -p zlint-cli -- mcp
```

The third response is a reject with score 45.

## Simulated co-signer

`zlint share init --path share.json` writes a simulated share file. Stderr says it is not a Zcash key. Stdout is empty.

`zlint cosign` and `zlint serve` open that file. They refuse a FROST share. The error says the share signs a PCZT sighash, not a proposal.

```text
cargo run -p zlint-cli -- cosign \
  --policy config/policy.example.yaml \
  --activity fixtures/demo_activity.json \
  --proposal fixtures/proposals/clean_accept.json \
  --db /tmp/zlint.db \
  --share /tmp/zlint-share.json
```

An accept returns a simulated share string. A reject returns no share. A warning returns no share until `zlint confirm --proposal` runs on this machine, which then returns the simulated share. The cap counts the spend only when a share is written.

`zlint serve` binds a Unix socket, mode 0600. One JSON line, method `cosign`, 64 KiB, 30 seconds. Any other method, including `confirm`, is refused: confirm stays on this machine. `zlint propose --socket --proposal` is the client. It does not open a share file.

## FROST co-signer

`zlint frost keygen` deals a fresh 2-of-2 RedPallas key and writes both files at mode 0600. It refuses an existing file. Stdout is empty. Stderr is:

```text
this process saw both shares. share 1 is for the agent. share 2 stays on this machine. this is a trusted dealer, not distributed key generation. this does not broadcast.
wrote <share1>
wrote <share2>
```

Share 1 is for the agent. Share 2 stays with the co-signer. This is not distributed key generation.

The agent builds the PCZT. Zlint does not. The round is:

1. `zlint frost prepare --share <share1> --nonce <nonce1> --pczt <file>` writes share 1's nonce (mode 0600) and prints the public commitment. Stderr: `commitment is ready. the nonce file stays on this machine.`
2. Start `zlint frost serve --socket <path> --policy <yaml> --activity <json> --db <sqlite> --share <share2> --nonce <nonce2>`. Startup stderr: `listening on <path>. share 2 stays in this process.` The socket is mode 0600. Methods are `commit` and `sign`. `confirm` is refused.
3. `zlint frost commit --socket <path> --pczt <file> --at <unix ms>` asks for share 2's public commitment. On accept, the server writes its nonce. On warn, it stores a pending warning and returns no commitment. On reject, it writes no nonce.
4. A person on this machine confirms a warning with `zlint confirm --policy --activity --db --share <share2> --pczt <file> --at <unix ms>`. Stdout has the decision, `"signature_share": null`, and `"confirmed": true`. Stderr: `confirmed. no signature share was written.`
5. `zlint frost sign --socket <path> --pczt <file> --at <unix ms> --commitment <agent commitment file>` returns share 2's signature share. The server deletes its nonce before it signs, then counts the accept. The identity is the hex shielded sighash. Asking again returns `already_signed` and no second share.
6. `zlint frost contribute --share <share1> --nonce <nonce1> --pczt <file> --theirs <co-signer commitment file>` prints share 1's signature share and deletes that nonce. Stderr: `wrote a signature share. the nonce file was deleted.`

The agent aggregates the two shares and broadcasts. There is no aggregate command in this tree. One share does not authorize the spend. Client stderr for `commit` and `sign` is `received a co-signer response.` Stdout is pretty JSON.

Policy and activity are process flags. The server reloads them on each request. A later reject deletes a matching nonce and does not sign.

## MCP co-signer

`zlint frost mcp` takes `--policy`, `--activity`, `--db`, `--share` (FROST share 2), and `--nonce`. A simulated share, or share 1, fails before it serves. The only tool is `cosign_pczt`. Confirm is not a tool. The same `initialize` / `tools/list` / `tools/call` flow as advice MCP applies. The server name is `zlint`.

`cosign_pczt` requires `proposed_at_ms`. Pass `pczt_path` or `pczt_hex`, not both. Omit `commitment` for round 1. Pass the other signer's public commitment object for round 2. Any other argument, including `policy_path`, is rejected: policy and activity stay on this machine.

The text content is pretty JSON:

- Round 1 accept: `decision` and `commitment`. No signature share.
- Round 2 accept: `decision` and `signature_share`. The nonce is already deleted.
- Warn before confirm: `decision` and `awaiting_confirmation: true`. No commitment and no nonce.
- Reject: `decision`. No share and no nonce.
- Already signed: `already_signed: true`. No second share.

`isError` is false for those decisions, including reject and an unconfirmed warning. `isError` is true for a bad input. The response is not a signed PCZT.

## When a person confirms

A person confirms only a warning. An accept signs with no one present. A reject never signs, and `zlint confirm` cannot overrule it.

A warning means the spend is inside the hard limits and the privacy score landed in the middle. On the example policy that is a score from 60 up to but not including 75. The pattern looks linkable: too soon after a similar receive, a round amount, soon after a shield, or change that is almost the whole input. The policy does not auto-approve that, and it does not auto-block it.

On the FROST path, `zlint confirm` records the confirmation and does not return a signature share. The agent's next round produces share 2. The agent cannot be the one who confirms. If it could, a warning would be an accept with an extra step. Confirm is not a socket method and not an MCP tool. It runs only as `zlint confirm` on the machine that holds share 2.

A simulated share is the exception. On that path `zlint confirm` returns the dummy share itself. That string is not a Zcash signature.
