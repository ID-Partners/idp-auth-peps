# Security

These are Policy Enforcement Points: a bug here is an authorisation bypass or an outage
for whatever sits behind them. Reports are welcome and taken seriously.

## Reporting a vulnerability

Report it privately through GitHub — **Security → Report a vulnerability** on this
repository — rather than in an issue or a pull request. Include what you ran, what you
expected and what happened; a request that reproduces it is worth more than a
description of it. Expect an acknowledgement within three working days.

Please give us a reasonable time to fix it before disclosing. We will credit you in the
release notes unless you would rather we did not.

## Supported versions

Fixes go into the latest minor release. Every component — the `coaz-pep` image, both
Kong plugins, the PingAccess rule and the Node SDK — shares one version line.

| Version | Supported |
| --- | --- |
| 0.4.x | Yes |
| < 0.4 | No — 0.4.0 closed authorisation bypasses in every enforcement point; upgrade |

## What we treat as a vulnerability

- A request permitted that the PDP did not permit, or permitted on a different reading of
  the request than the one the upstream acts on.
- A deny or a refusal that fails open, or a fail-open permit that is not marked.
- A token, proof or trust chain accepted when it should not verify.
- A way for a client to reach, or read from, a host the allowlists do not permit.
- A way for a client to take the PEP down.

`PEP_ALLOW_INSECURE`, `allow_insecure` and `allowInsecure` turn off protections on
purpose, for development. What happens with them set is not a vulnerability; that they
can be set by accident in production would be.
