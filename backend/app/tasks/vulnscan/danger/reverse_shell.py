"""Reverse-shell possibility assessment — documentation and detection only.

For each command-injection candidate this module describes *whether* the
observed context could support an interactive shell and *what evidence would
confirm it*. It deliberately contains no connecting payloads, no listener, and
no execution path. Shell families are named so an authorized tester knows where
to look manually; the concrete commands are not generated here.
"""

from __future__ import annotations

import logging

from app.tasks.vulnscan.danger.budget import danger_finding, evidence_block, truncated

logger = logging.getLogger("recontitan.danger.reverse_shell")

MODULE = "reverse_shell_assessment"

A03 = "A03:2021-Injection"

#: Interpreter families that *typically* exist on a host reachable by an
#: injection point. Named only; no payload text is stored or produced.
SHELL_FAMILIES: tuple[tuple[str, str], ...] = (
    ("bash / sh", "POSIX shell with network redirection support on most Linux hosts"),
    ("netcat (nc / ncat)", "Present on many minimal images and appliance firmware"),
    ("python", "Common on application servers and CI runners"),
    ("php", "Present wherever the injection point is served by a PHP application"),
    ("perl", "Frequently installed as a base-system dependency on Linux distributions"),
    ("powershell", "Applies when the blind context indicates a Windows backend"),
)

CONFIRMATION_EVIDENCE = {
    "direct output": (
        "The canary string appears verbatim in the HTTP response body, so the injected command's stdout is "
        "returned. Confirmation is a single authorized command whose output is unique and observable "
        "(for example a fixed random string) executed with the asset owner's written approval."
    ),
    "blind": (
        "No command output is returned. Confirmation requires a side channel the tester controls and is "
        "authorized to use: a measurable execution delay, or a DNS or HTTP callback to infrastructure named in the "
        "rules of engagement. ReconTitan does not open either channel."
    ),
}


def assess_reverse_shell_vectors(target: str, candidates: list[dict]) -> list[dict]:
    """Emit one sub-finding per command-injection candidate.

    ``candidates`` are the dictionaries recorded by
    :func:`app.tasks.vulnscan.danger.injection.run_command_injection`.
    """
    if not candidates:
        return [danger_finding(
            tool=MODULE,
            category="danger_reverse_shell",
            severity="info",
            title="Reverse Shell Assessment - no command-injection candidates",
            description=(
                "No command-injection candidate was recorded, so no input point was assessed as a potential "
                "interactive-shell vector. This reflects the bounded probes that were sent, not a guarantee that "
                "no such vector exists."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("Command injection candidates", 0),
                ("Connection attempted", "no - ReconTitan never connects a shell"),
            ]),
            owasp=A03,
            asset=target,
        )]

    findings: list[dict] = []
    for candidate in candidates[:25]:
        context_kind = candidate.get("context", "blind")
        severity = "high"
        families = "\n" + "\n".join(f"  {name} - {why}" for name, why in SHELL_FAMILIES)
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_reverse_shell",
            severity=severity,
            title=f"Reverse Shell Possibility ({context_kind}) - {candidate.get('parameter', 'unknown')}",
            description=(
                f"A command-injection candidate was recorded at this input point in {context_kind} context. If the "
                "injection is real, the same execution primitive would support an interactive outbound shell using "
                "any interpreter present on the host. ReconTitan did not attempt, stage, or generate a connecting "
                "payload and made no outbound connection from the target. This entry documents the vector and the "
                "evidence that would confirm it so an authorized tester can validate it under the rules of "
                "engagement."
            ),
            evidence=evidence_block([
                ("Method", candidate.get("method", "GET")),
                ("Endpoint", truncated(str(candidate.get("url", "")), 300)),
                ("Parameter", candidate.get("parameter", "unknown")),
                ("Input point type", candidate.get("input_type", "unknown")),
                ("Injection context", context_kind),
                ("Detection signal", candidate.get("signal", "unknown")),
                ("Probe category", candidate.get("payload_category", "unknown")),
                ("Hypothetical interpreter families", families),
                ("Evidence that would confirm", CONFIRMATION_EVIDENCE.get(context_kind, CONFIRMATION_EVIDENCE["blind"])),
                ("Connection attempted by ReconTitan", "no"),
                ("Payload generated by ReconTitan", "no"),
            ]),
            remediation=(
                "Remove the shell invocation from this code path. If a subprocess is unavoidable, use an argument "
                "array rather than a shell string, validate input against a strict allow-list, drop the process to "
                "the least privilege it needs, and add egress filtering so the host cannot open arbitrary outbound "
                "connections."
            ),
            owasp=A03,
            attack_vector=f"Potential interactive shell via command injection ({context_kind})",
            asset=str(candidate.get("url", target)),
        ))

    logger.info("[danger:reverse_shell] documented %d vector(s) for %s", len(findings), target)
    return findings
