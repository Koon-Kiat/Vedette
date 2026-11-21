"""Template explanation used when the model's answer cannot be used.

A finding always gets a usable explanation: if the model answers with
something invalid twice, this text (built only from the trusted rule
definition and the defanged target) is stored instead.
"""

from vedette.llm.guards import slug
from vedette.llm.schema import Analysis
from vedette.notify.defang import clean_text, defang
from vedette.rules.model import RuleSpec
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
    )
