# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
[security advisory form](https://github.com/woodhouseog/x402-digital-vending-machine/security/advisories/new).
Do not disclose an unresolved vulnerability in a public issue.

Include the affected version or commit, a minimal reproduction, the expected
impact, and any suggested mitigation. Reports involving payment requirement
validation, wallet or key handling, receipt verification, replay protection,
or recovery-token exposure are especially useful.

You can expect an initial acknowledgement within five business days. A fix and
disclosure timeline will be coordinated after the report is reproduced and
triaged.

## Supported versions

Security fixes are applied to the latest released version. Users should update
to the newest release before reporting a problem that may already be fixed.

## Secret-handling guidance

- Never include a wallet private key, seed phrase, recovery token, payment
  authorization, or production credential in a report.
- Redact transaction data that is not required to reproduce the issue.
- The client is designed to read signing material locally. Do not send private
  key material to the service or commit it to this repository.
