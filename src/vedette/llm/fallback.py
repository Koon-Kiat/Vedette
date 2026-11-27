"""Template explanation used when the model's answer cannot be used.

A finding always gets a usable explanation: if the model answers with
something invalid twice, this text (built only from the trusted rule
definition and the defanged target) is stored instead. The rule's analyst
notes, trusted text from the rules file, fill in the harmless look-alikes and
the checks.
"""

from vedette.llm.guards import slug
from vedette.llm.prompts import MAX_CHECKS, MAX_EXPLANATIONS
from vedette.rules.model import RuleSpec
from vedette.shared.defang import clean_text, defang
from vedette.shared.models import Analysis
from vedette.storage.store import StoredFinding

_ACTIONS = {
    "new-device": (
        "Check whether you recognise this device or address; if not, review what is "
        "connected to your network."
    ),
    "young-domain": (
        "Find out which device visited this domain and why; treat any login or download "
        "from it with suspicion."
    ),
    "threat-intel-allowed": (
        "Identify the device that made the query, scan it for malware, and add the domain "
        "to your NextDNS denylist."
    ),
    "dga-like": "Identify the device that made the query and check it for unfamiliar software.",
    "tunnel-like": (
        "Identify the device and the program making these queries; block the domain if you "
        "do not recognise it."
    ),
    "tunnel-slow": (
        "Identify the device and the program making these queries; block the domain if you "
        "do not recognise it."
    ),
    "dga-burst": (
        "Check the device for malware: look at which program made these lookups and scan "
        "it; the sample domains show what it was trying."
    ),
    "volume-spike": (
        "Check what the device was doing at that time; investigate further if the burst "
        "was unexpected."
    ),
    "blocked-burst": (
        "Look at which blocked domains were requested and check the device for adware or "
        "unwanted apps."
    ),
    "new-destination-category": (
        "Check whether this new kind of activity is expected for the device."
    ),
}
_DEFAULT_ACTION = "Review the evidence and decide whether the activity is expected."
_CAUSE = "Not analysed by the local model; this is the rule's standard explanation."


def template_analysis(finding: StoredFinding, spec: RuleSpec | None) -> Analysis:
    """Build the fallback explanation for a finding at its rule's severity floor."""
    description = clean_text(spec.description if spec is not None else "", limit=260)
    target = defang(clean_text(finding.target, limit=100))
    summary = f"{description} Concerns: {target}.".strip()[:400]
    notes = spec.analyst_notes if spec is not None else None
    look_alikes = notes.look_alikes if notes is not None else []
    checks = notes.checks if notes is not None else []
    return Analysis(
        finding_id=finding.id,
        summary=summary,
        likely_cause=_CAUSE,
        recommended_action=_ACTIONS.get(finding.rule_id, _DEFAULT_ACTION)[:300],
        priority=finding.severity,
        group_key=slug(f"{finding.rule_id}-{finding.target}"),
        confidence=0.0,
        source="template",
        model=None,
        harmless=tuple(clean_text(text, limit=300) for text in look_alikes[:MAX_EXPLANATIONS]),
        checks=tuple(clean_text(text, limit=300) for text in checks[:MAX_CHECKS]),
    )
