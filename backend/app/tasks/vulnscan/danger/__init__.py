"""Danger Mode — bounded penetration-test simulation modules.

Every module in this package is non-destructive by construction:

* No target data is created, modified, or deleted.
* No authentication is attempted against live accounts.
* No shell is ever connected; command-injection vectors are reported only.
* Secrets, tokens, and object contents are fingerprinted, never stored verbatim.
* Every emitted finding carries ``requires_manual_validation=True``.

The package is inert unless ``ALLOW_DANGER_MODE=true`` and the operator supplied
the typed authorization acknowledgement.
"""
