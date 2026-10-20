# Independent Security Review Protocol

Version: 1

Assess the exact change and its trust boundaries: input validation, authorization, secrets, credentials, external dependencies, file and network access, CI execution, signing, artifact publication, logging, and rollback. Trace who can modify evidence and who can publish or approve results.

Record relevant threats, mitigations, residual risks, findings, reviewed revision, and the scope of verification. Review whether untrusted code can reach privileged credentials or alter trusted results. Require additional proof for unknown or sensitive risks, and block release while material findings remain unresolved.

A signed artifact establishes only its authenticated bytes under an approved trust anchor. It does not prove product tests, independent review, or any particular CI or verifier result.
