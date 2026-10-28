# Zlint

Zlint checks a shielded Zcash spend before it goes out and says yes, no, or warn, with a reason.

Shielded ZEC hides the amount and the parties on the chain. The pattern around the spend can still give you away: the same size as a payment you just received, a tidy round number, money shielded and then spent a few minutes later, or a change output that is almost the whole input. Zlint looks at that pattern, and at the spending limits you set.

## Why

A wallet can hide those details from the chain and still show them to the program that built the payment. Zlint is that check. Call it two ways.

- Advice. `decide`, `review`, and `zlint mcp` return the sentence. They do not hold a key and they do not sign. A caller that still has the spend key can spend anyway.
- Enforce. For an agent that must not finish an Orchard spend alone. The agent holds FROST share 1. This machine holds share 2. `zlint frost serve` and `zlint frost mcp` return one public commitment or one signature share only after the check accepts, or after a person confirms a warning on this machine. The agent aggregates the two shares and broadcasts. Zlint does neither.

A wallet can opt into the same co-signer. Downtime then freezes the spend. That is the cost of a no the agent cannot skip.

## How

The spend is the PCZT a wallet or an agent already built. Zlint reads the amount, the destination, and the change from it. A person does not type those fields.

The history stays with the co-signer. Receives and shields come from an incoming viewing key on this machine. Spends it has already accepted stay in its own log. The agent sends the transaction and a time. Enforce does not take that history from the agent. An agent that writes the history can leave out the receive that would make the check say no.

Advice can still be asked with an activity file. That is a second opinion, and it is what the fixtures use. The co-signer does not treat that file as its source of truth.

Zlint scores the spend against your policy.

- A broken limit is a no. Too large for one payment, over the daily cap, not on the allowlist, or too many spends in the last hour.
- A clean spend is a yes.
- A leaky-looking spend that still respects the limits is a warning.

The score starts at 100. Each pattern that fires takes points off once: paying soon after a similar receive, a round or repeated amount, spending soon after a shield, and change that is almost the entire input. Drop far enough and a warning becomes a no. The exact cutoffs are in the policy file.

Zlint does not broadcast. Nothing in Zlint is enforced by the Zcash chain. The commands in this tree still read an activity file the caller passes. The co-signer scan above is not in this build yet.

## Try it

Install Rust, then from this directory:

```text
cargo run -p zlint-cli -- decide \
  --policy config/policy.example.yaml \
  --activity fixtures/demo_activity.json \
  --proposal fixtures/proposals/timing_reject.json
```

That example is a no: half a ZEC, four minutes after a half-ZEC receive. The sentence is printed on its own so you can read why.

The other cases, and the co-signer commands, are in [docs/HOW_TO_USE.md](docs/HOW_TO_USE.md). `cargo test --workspace` runs the checks.

## Asking from another program

A wallet, a chat tool, or an agent on this machine can ask without a shell. The usual way those tools call a local helper is called MCP.

`zlint mcp` is advice. The tools are `propose_spend` and `review_pczt`. The answer does not sign, and it is not written to the log.

`zlint frost mcp` is the co-signer. The tool is `cosign_pczt`. Share 2 stays in that process. Confirm is not a tool. Omit the other signer's commitment for round 1. Pass it for round 2. The result is a public commitment or one signature share, plus the decision. It is not a finished transaction.

How to point a tool at either server is in [docs/HOW_TO_USE.md](docs/HOW_TO_USE.md).

## What this build does not do

It does not hold a viewing key, talk to a node, build the proof, or broadcast. `zlint frost keygen` is a trusted dealer: that process sees both shares. It is not distributed key generation. A simulated share from `zlint share init` is not a Zcash signature. Mode 0600 on the share files does not stop someone who can read both files on this account. A refusal on the advice path does not freeze the coins. The longer version is [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md).

## More detail

| | |
|--|--|
| [docs/HOW_TO_USE.md](docs/HOW_TO_USE.md) | Commands and the sample spends |
| [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) | What not to claim |
| [config/policy.example.yaml](config/policy.example.yaml) | The default limits |
