# Security policy

CodeSentinel is a security assessment tool. Use it only on systems you own or have explicit, written authorization to assess. Configure the exact authorized host in `ALLOWED_TARGET_HOSTS`; never use broad suffixes such as `com` or `net`. Private and loopback targets are blocked unless `ALLOW_PRIVATE_TARGETS=true` is explicitly set for a controlled lab. The Compose demo enables that setting only to reach the isolated `test-api` service; the service has synthetic data and no host-published port.

The scanner uses low-volume GET/HEAD/OPTIONS requests only, does not follow redirects, caps request count and timeouts, disables environment proxy inheritance, and rejects targets outside the allowlist. It does not attempt denial of service, brute force, state changes, or destructive actions. Its checks are heuristic and evidence-based; a Potential or Inconclusive status is not a confirmed vulnerability, and a clean report is not proof of security.

Reports intentionally do not store response bodies, authorization tokens, or credentials. JWT signing secrets and database passwords must be unique and protected for any use beyond local development. Local demo defaults are not production credentials. Before organizational deployment, conduct a threat model, harden secret management, add rate limiting and audit logging, review SSRF/DNS rebinding defenses, use TLS, validate database migrations and backups, and obtain independent security review.

Please do not submit real production credentials or sensitive response data in issue reports. For suspected vulnerabilities in CodeSentinel, provide a minimal reproducible report without secrets.
