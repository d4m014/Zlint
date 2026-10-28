# Trust model

Zlint trust model.

- Advice (`decide`, `review`, `zlint mcp`) does not hold a spend key or a signature share. A caller that spends anyway is not stopped.
- Enforce holds share 2 of a trusted-dealer 2-of-2 RedPallas key (Orchard spend auth). Share 1 is for the agent. A no stops that Orchard spend only while the agent needs this share. If the co-signer is down, the spend is frozen. A replaced program with share 2 can ignore the policy. Someone who can read both share files on this account is not stopped by mode 0600.
- `zlint frost keygen` is a trusted dealer. That process sees both shares. It is not distributed key generation. It does not broadcast.
- A simulated share (`zlint share init`, `zlint cosign`, `zlint serve`) is not a Zcash signature. Those commands refuse a FROST share. `zlint frost serve` and `zlint frost mcp` refuse a simulated share.
- A warning is not a yes. Confirm stays on this machine. The agent cannot call it. For a FROST share, `zlint confirm` records the confirmation and does not emit a signature share. The next signing round does.
- The check is a heuristic. It flags patterns an observer could use. It does not compute an anonymity set and it does not prove unlinkability.
- Nothing on chain enforces the policy. A shielded spend hides the amount, the parties, and the change, which is the pattern the check looks at. The chain cannot see it, so the chain cannot reject it.
- The privacy score is local arithmetic over the checks in the build plan. It is not a probability.
- Zlint does not build the proof and does not broadcast. A live zebra or zcashd node is not required. Do not describe this tree as mainnet.

Out of model: a claim that Zlint makes shielded ZEC fully private, that advice mode freezes funds, or that one signature share is a finished transaction.
