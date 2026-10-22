# Security Policy

## Supported versions

Kist is alpha software. Security fixes are applied to the latest release only.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately via [GitHub Security Advisories](https://github.com/nitonrock/kist/security/advisories/new)
or by email to info@nitonrock.com. Include affected version, reproduction steps, and impact.

You can expect an acknowledgement within 5 working days. Please allow time for a fix
and coordinated disclosure before publishing details.

## Verifying releases

From 0.2.7, releases are published to PyPI only by the
[release workflow](.github/workflows/release.yml), through Trusted Publishing, with
signed attestations. Verify a file with:

```bash
uvx pypi-attestations verify pypi --repository https://github.com/nitonrock/kist pypi:kist-<version>-py3-none-any.whl
```

A Kist release without an attestation, from 0.2.7 on, was not published by this
repository: do not install it, and please report it.

## Scope notes

Kist has not yet undergone an independent security audit. See the
[threat model](THREAT_MODEL.md) for what Kist protects, from whom, and where it stops,
and the [format specification](FORMAT.md) for the exact bytes. Reports that show the
threat model is wrong are welcome too.
