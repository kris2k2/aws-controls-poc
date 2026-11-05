"""Report: a visual HTML summary of one run (ADR-0010).

`report.html` is for the people who decide on a release and the teams who
operate the service: what the service is, the threat vectors its controls
answer, what is actually implemented (guardrails proved by Verify, detective
and plan-time artifacts) and what is left open. It is a view over the files
the stages wrote (capability-profile, selection, controls, generation,
verification, review). It decides nothing and adds nothing: a fact that
isn't in those files isn't in the report.

Placement comes from Compose (`composition.json`): where each policy is
attached, the quota use on each node, and the changes to the organization.

The page is one self-contained file: inline CSS, no scripts, no fonts or
images from elsewhere, and a Content-Security-Policy that forbids them.
Every value from the run is HTML-escaped, and only https links are made
clickable. It is deterministic: the same run gives the same bytes, with no
clock of its own (the date shown is the review's).
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from . import __version__

# Threat vectors by control objective: the attacker's goal a control answers.
CATEGORIES = {
    "exfiltration": ("Data exfiltration", "Data leaves the organization, its network or its Regions."),
    "access": ("Unauthorized access", "Someone outside the authorized scope uses the service or reaches its data."),
    "escalation": ("Privilege escalation", "Someone takes over the exemptions given to break-glass and exception roles."),
    "evasion": ("Defense evasion", "Activity is hidden from logging, configuration recording or detection."),
    "misconfiguration": ("Insecure configuration", "Resources run with weaker settings than the baseline."),
    "abuse": ("Cost and accountability", "Spend or resources that can't be bounded, tracked or attributed."),
    "other": ("Other", "Controls whose objective has no threat vector recorded here yet."),
}
OBJECTIVES = {
    "region-containment": ("exfiltration", "Workloads and data placed in Regions outside the allowed set"),
    "resource-perimeter": ("exfiltration", "Organization credentials used to copy data to buckets outside the organization"),
    "data-perimeter": ("exfiltration", "The organization's VPC endpoints used with outside credentials, or to reach outside resources"),
    "no-data-egress": ("exfiltration", "Federated or cross-account data catalogs that move data across the boundary"),
    "identity-perimeter": ("access", "Principals outside the organization reaching its S3 objects and KMS keys"),
    "preview-accounts": ("access", "The service used outside the authorized preview accounts"),
    "network-perimeter": ("access", "Stolen credentials used against the API from outside the organization's network"),
    "no-external-sharing": ("access", "Excluded capabilities (Spark sessions, notebooks) used to run code and share results"),
    "privilege-escalation": ("escalation", "Break-glass or exception roles created, changed or passed to inherit their exemptions"),
    "logging-tamper": ("evasion", "The audit trail stopped or reconfigured to hide activity"),
    "detection-tamper": ("evasion", "Configuration recording stopped to hide drift"),
    "guardrail-detection": ("evasion", "Probing of guardrails and use of break-glass going unnoticed"),
    "config-recording": ("evasion", "Service resources missing from configuration history"),
    "logging": ("evasion", "Query activity without metrics or logs"),
    "enforced-configuration": ("misconfiguration", "Clients overriding workgroup settings such as encryption and result location"),
    "encryption": ("misconfiguration", "Query results stored without a key the organization controls"),
    "results-location": ("misconfiguration", "Query results written to a bucket someone else owns"),
    "hygiene": ("misconfiguration", "Resources left on outdated engine versions"),
    "inventory": ("abuse", "Resources nobody can identify or own"),
    "attribution": ("abuse", "Spend that can't be attributed to a cost center"),
    "resource-limits": ("abuse", "Runaway queries with no limit on the data scanned (denial of wallet)"),
}
GUARDRAILS = ("scp", "rcp", "vpce")
LAYERS = (  # strongest first
    ("prevented", "Prevented", "a guardrail denies it at the API"),
    ("plan-time", "Plan-time", "a Sentinel policy stops it in Terraform plans only"),
    ("detected", "Detected", "a Config rule or detection reports it"),
    ("gap", "Not covered", "nothing is generated for it in this run"),
)
PLATFORM_LABELS = {"scp": "SCP", "rcp": "RCP", "vpce": "Endpoint", "boundary": "Boundary", "config": "Config",
                   "cloudtrail": "CloudTrail", "sentinel": "Sentinel"}
CLASS_ORDER = {"Containment": 0, "Supervision": 1, "Hardening": 2}
DECISIONS = {"release": "Released", "hold": "On hold", "blocked": "Blocked", None: "Not reviewed"}


class ReportError(ValueError):
    pass


def _read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read {path}: {exc}") from exc


def load(run: Path, review: dict | None = None) -> dict:
    """The run files the report reads. `review` replaces the run's review.json (Deliver passes its own)."""
    files = {name: _read(run / f"{name}.json") for name in
             ("capability-profile", "selection", "generation", "verification", "review", "assessment",
              "composition")}
    if files["selection"] is None or files["generation"] is None:
        raise ReportError(f"{run} has no selection.json or generation.json: run select and generate first")
    files["controls"] = {p.stem: _read(p) for p in sorted((run / "controls").glob("*.json"))}
    files["policies"] = {p.stem: _read(p) for p in sorted((run / "org-policies").glob("*.json"))}
    if review is not None:
        files["review"] = review
    return files


# ---------------------------------------------------------------- model


def coverage(statuses: dict) -> list[str]:
    """The layers a control has in this run, strongest first; ["gap"] if none."""
    generated = {p for p, s in statuses.items() if s.get("status") == "generated"}
    layers = []
    if generated & set(GUARDRAILS):
        layers.append("prevented")
    if "sentinel" in generated:
        layers.append("plan-time")
    if generated & {"config", "cloudtrail"}:
        layers.append("detected")
    return layers or ["gap"]


def _ordered(controls: dict) -> list[tuple[str, dict]]:
    return sorted(controls.items(), key=lambda kv: (CLASS_ORDER.get(kv[1].get("class"), 9), kv[0]))


def mutants(proof: dict) -> str:
    """"12 of 12 mutants caught", with the equivalent ones (which change nothing observable) set apart."""
    m = proof.get("mutants", {})
    equivalent = m.get("equivalent", 0)
    text = f"{m.get('caught', 0)} of {m.get('total', 0) - equivalent} mutants caught"
    return text + (f", {equivalent} equivalent" if equivalent else "")


def threat_of(record: dict) -> tuple[str, str]:
    objective = record.get("objective", "")
    if objective in OBJECTIVES:
        return OBJECTIVES[objective]
    if objective.startswith("security-hub"):
        return "misconfiguration", record.get("title", objective)
    return "other", record.get("title", objective)


def threats(files: dict) -> list[dict]:
    """Threat vectors grouped by category, each with its controls, coverage and residual risks."""
    statuses = files["generation"].get("controls", {})
    proofs = {p["control_id"]: p for p in (files.get("verification") or {}).get("proofs", [])}
    risks = (files.get("verification") or {}).get("accepted_risks", [])
    vectors: dict[tuple[str, str], dict] = {}
    for cid, record in _ordered(files["controls"]):
        category, statement = threat_of(record)
        vector = vectors.setdefault((category, statement), {
            "category": category, "threat": statement, "controls": [], "blind_spots": [], "risks": []})
        layers = coverage(statuses.get(cid, {}))
        vector["controls"].append({"id": cid, "title": record.get("title", ""), "mode": record.get("mode"),
                                   "layers": layers, "proof": proofs.get(cid)})
        vector["blind_spots"] += [b for b in record.get("blind_spots", []) if b not in vector["blind_spots"]]
        vector["risks"] += [r for r in risks if cid in r.get("controls", []) and r not in vector["risks"]]
    for vector in vectors.values():
        best = min(LAYERS.index(next(l for l in LAYERS if l[0] == c["layers"][0])) for c in vector["controls"])
        vector["coverage"] = LAYERS[best][0]
    order = list(CATEGORIES)
    return sorted(vectors.values(), key=lambda v: (order.index(v["category"]), v["threat"]))


# ---------------------------------------------------------------- html


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _link(url: str, text: str | None = None) -> str:
    label = _e(text or url)
    return f'<a href="{_e(url)}" rel="noreferrer">{label}</a>' if str(url).startswith("https://") else label


def _chip(text: str, kind: str, title: str = "") -> str:
    tip = f' title="{_e(title)}"' if title else ""
    return f'<span class="chip {_e(kind)}"{tip}>{_e(text)}</span>'


def _tile(value, label: str, note: str = "") -> str:
    return (f'<div class="tile"><div class="value">{_e(value)}</div><div class="label">{_e(label)}</div>'
            + (f'<div class="note">{_e(note)}</div>' if note else "") + "</div>")


def _bar(parts: list[tuple[str, int, str]]) -> str:
    """A stacked bar: (label, count, css class)."""
    total = sum(n for _, n, _ in parts) or 1
    segs = "".join(f'<span class="seg {_e(k)}" style="width:{100 * n / total:.2f}%" title="{_e(l)}: {n}"></span>'
                   for l, n, k in parts if n)
    legend = "".join(f'<li><span class="dot {_e(k)}"></span>{_e(l)} <b>{n}</b></li>' for l, n, k in parts)
    return f'<div class="bar" role="img" aria-label="{_e(", ".join(f"{l} {n}" for l, n, _ in parts))}">{segs}</div>' \
           f'<ul class="legend">{legend}</ul>'


def _service(files: dict) -> str:
    profile = files.get("capability-profile") or {}
    generation = files["generation"]
    services = profile.get("services") or []
    tiers: dict[str, int] = {}
    resources, keys = [], []
    for s in services:
        for tier, n in (s.get("summary", {}).get("actions_by_risk_tier") or {}).items():
            tiers[tier] = tiers.get(tier, 0) + n
        resources += [r.get("resource_type") if isinstance(r, dict) else r for r in s.get("resource_types", [])]
        keys += [k.get("condition_key") if isinstance(k, dict) else k for k in s.get("condition_keys", [])]
    deps = [p for p in generation.get("allow_list_prefixes", []) if p != generation.get("service")]
    out = ['<section id="service"><h2>The service</h2>']
    if not services:
        out.append("<p class=\"muted\">No capability profile in this run: Resolve hasn't run.</p>")
    else:
        out.append('<div class="grid two"><div class="card"><h3>API surface by risk tier</h3>')
        out.append(_bar([(t, n, f"tier-{t}") for t, n in sorted(tiers.items(), key=lambda kv: -kv[1])]))
        out.append(f'<p class="muted">{sum(tiers.values())} actions from the AWS service reference '
                   f'({_e(", ".join(profile.get("prefixes", [])))}).</p></div>')
        out.append('<div class="card"><h3>Resources and condition keys</h3><dl>')
        out.append(f"<dt>Resource types</dt><dd>{' '.join(_chip(r, 'plain') for r in resources if r) or '—'}</dd>")
        out.append(f"<dt>Condition keys</dt><dd>{' '.join(_chip(k, 'plain') for k in keys if k) or '—'}</dd>")
        out.append(f"<dt>Dependencies on the allow-list</dt><dd>{' '.join(_chip(d, 'plain') for d in deps) or '—'}</dd>")
        out.append("</dl></div></div>")
        gaps = profile.get("not_yet_assessed") or []
        if gaps:
            out.append('<p class="muted">Not assessed yet: ' + _e("; ".join(gaps)) + ".</p>")
    out.append("</section>")
    return "".join(out)


def _threats(files: dict, vectors: list[dict]) -> str:
    counts = {k: sum(v["coverage"] == k for v in vectors) for k, _, _ in LAYERS}
    out = ['<section id="threats"><h2>Threat vectors</h2>',
           '<p class="muted">Each vector is the attacker goal a selected control answers, and its coverage is the '
           'strongest layer this run generates for it. Accepted risks are the gaps left open on purpose; blind '
           'spots are what the controls say they can\'t see.</p>',
           _bar([(label, counts[k], f"cov-{k}") for k, label, _ in LAYERS])]
    spec = (files.get("verification") or {}).get("spec") or {}
    if spec:
        out.append(f'<p class="muted">Proofs are against the {_e(spec.get("service"))} security spec: '
                   f'{_e(spec.get("status"))}.</p>')
    for category, (title, blurb) in CATEGORIES.items():
        group = [v for v in vectors if v["category"] == category]
        if not group:
            continue
        out.append(f'<h3 class="category">{_e(title)} <span class="muted">{_e(blurb)}</span></h3><div class="flow">')
        for v in group:
            label = next(l for k, l, _ in LAYERS if k == v["coverage"])
            out.append(f'<article class="card threat cov-{_e(v["coverage"])}-edge"><header>'
                       f'{_chip(label, "cov-" + v["coverage"])}<h4>{_e(v["threat"])}</h4></header><ul class="controls">')
            for c in v["controls"]:
                layers = " ".join(_chip(next(l for k, l, _ in LAYERS if k == layer), "cov-" + layer + " small")
                                  for layer in c["layers"])
                proof = ""
                if c["proof"]:
                    proof = _chip(f"proof {c['proof'].get('result')} · {mutants(c['proof'])}",
                                  "ok small" if c["proof"].get("result") == "pass" else "bad small")
                out.append(f'<li><code>{_e(c["id"])}</code> {_e(c["title"])} <span class="muted">· {_e(c["mode"])}'
                           f'</span><div class="chips">{layers} {proof}</div></li>')
            out.append("</ul>")
            for r in v["risks"]:
                out.append(f'<div class="risk"><b>{_e(r.get("id"))} accepted risk</b> {_e(r.get("risk"))}'
                           f'<div class="muted">Reach: {_e(r.get("reach"))} · {_e(r.get("status"))}</div></div>')
            if v["blind_spots"]:
                out.append('<div class="muted blind">Blind spots: ' + _e("; ".join(v["blind_spots"])) + "</div>")
            out.append("</article>")
        out.append("</div>")
    out.append("</section>")
    return "".join(out)


def _guardrails(files: dict) -> str:
    generation = files["generation"]
    statuses = generation.get("controls", {})
    proofs = {p["control_id"]: p for p in (files.get("verification") or {}).get("proofs", [])}
    out = ['<section id="guardrails"><h2>Implemented guardrails</h2><div class="grid">']
    for name, info in sorted((generation.get("policies") or {}).items()):
        doc = files["policies"].get(name) or {}
        n = len(doc.get("Statement", []))
        used = 100 * info.get("characters", 0) / (info.get("limit") or 1)
        out.append(f'<div class="card policy"><h3><code>{_e(name)}</code></h3><p>{n} statement{"s" * (n != 1)} · '
                   f'{_e(info.get("characters"))} of {_e(info.get("limit"))} characters</p>'
                   f'<div class="meter{" over" if info.get("over_limit") else ""}"><span style="width:{min(used, 100):.1f}%">'
                   f'</span></div></div>')
    out.append("</div>")
    out.append('<div class="table-wrap"><table><thead><tr><th>Control</th><th>Class</th><th>Severity</th><th>Mode</th>'
               + "".join(f"<th>{_e(PLATFORM_LABELS[p])}</th>" for p in PLATFORM_LABELS) + "<th>Proof</th></tr></thead><tbody>")
    for cid, record in _ordered(files["controls"]):
        cells = []
        for platform in PLATFORM_LABELS:
            s = statuses.get(cid, {}).get(platform, {})
            status = s.get("status", "")
            text = {"generated": "✓", "not_deployed": "off", "pending": "pending",
                    "not_applicable": "n/a", "not_expressible": "can't"}.get(status, status or "—")
            cells.append(f'<td>{_chip(text, "st-" + status, s.get("reason") or s.get("file") or s.get("sid") or "")}</td>')
        proof = proofs.get(cid)
        proof_cell = _chip(proof["result"], "ok" if proof["result"] == "pass" else "bad", mutants(proof)) if proof else '<span class="muted">—</span>'
        out.append(f'<tr><th scope="row"><code>{_e(cid)}</code><div class="muted">{_e(record.get("title"))}</div></th>'
                   f'<td>{_e(record.get("class"))}</td><td>{_e(record.get("severity"))}</td><td>{_e(record.get("mode"))}</td>'
                   + "".join(cells) + f"<td>{proof_cell}</td></tr>")
    out.append("</tbody></table></div>")
    out.append('<p class="muted">✓ generated · off: selected but not deployed (reason on hover) · pending: not built '
               "or no definition yet · n/a: not applicable · can't: not expressible on that platform.</p>")
    notes = generation.get("detective_notes") or []
    if notes:
        out.append('<div class="card notes"><h3>Before deploying the detective artifacts</h3><ul>'
                   + "".join(f"<li>{_e(n)}</li>" for n in notes) + "</ul></div>")
    out.append("</section>")
    return "".join(out)


def _placement(files: dict) -> str:
    composition = files.get("composition")
    out = ['<section id="placement"><h2>Placement in the organization</h2>']
    if not composition:
        out.append('<p class="muted">Compose hasn\'t run on this run.</p></section>')
        return "".join(out)
    out.append(f'<p class="muted">{_e(composition.get("strategy", "").capitalize())} organization: '
               + ("an SCP allow is needed at every level from the root to the account, so the service is reachable "
                  "only where its allow-list is attached." if composition.get("strategy") == "allow-list" else
                  "FullAWSAccess on the root makes the service reachable everywhere, so its denies go on the root.")
               + "</p>")
    if composition.get("result") != "fits":
        out.append('<div class="card bad-edge"><h3>Over budget</h3><ul>'
                   + "".join(f"<li>{_e(p)}</li>" for p in composition.get("problems", [])) + "</ul></div>")
    removed = composition.get("removes_service_from") or []
    if removed:
        out.append(f'<div class="risk"><b>Removes {_e(composition.get("service"))}</b> from '
                   f'{_e(", ".join(removed))}: workloads there lose access.</div>')
    out.append('<div class="table-wrap"><table><thead><tr><th>Policy</th><th>Attached to</th><th>Why</th></tr></thead>'
               "<tbody>")
    for name, placement in sorted(composition.get("placements", {}).items()):
        targets = " ".join(_chip(t, "plain") for t in placement.get("targets", [])) or '<span class="muted">not attached</span>'
        out.append(f'<tr><th scope="row"><code>{_e(name)}</code></th><td>{targets}</td>'
                   f'<td class="muted">{_e(placement.get("why"))}</td></tr>')
    for name, endpoints in sorted(composition.get("endpoints", {}).items()):
        out.append(f'<tr><th scope="row"><code>{_e(name)}</code></th><td>'
                   f'{" ".join(_chip(e, "plain") for e in endpoints)}</td><td class="muted">every VPC endpoint the '
                   "organization runs</td></tr>")
    out.append("</tbody></table></div>")
    out.append('<div class="grid">')
    for b in composition.get("budgets", []):
        used = 100 * b.get("attached", 0) / (b.get("limit") or 1)
        out.append(f'<div class="card"><h3><code>{_e(b.get("target"))}</code> · {_e(str(b.get("type")).upper())}</h3>'
                   f'<p>{_e(b.get("attached"))} of {_e(b.get("limit"))} attached</p>'
                   f'<div class="meter{" over" if b.get("over") else ""}"><span style="width:{min(used, 100):.1f}%">'
                   f'</span></div><p class="muted">{_e(", ".join(b.get("policies", [])))}</p></div>')
    out.append("</div>")
    diff = composition.get("diff", {})
    changes: dict[str, int] = {}
    for d in diff.get("policies", []):
        changes[d["change"]] = changes.get(d["change"], 0) + 1
    moves = diff.get("attachments", [])
    out.append('<div class="card notes"><h3>Changes to the organization</h3><p>'
               + _e(", ".join(f"{n} to {k}" for k, n in sorted(changes.items())) or "none") + ".</p>")
    if moves:
        out.append('<p class="muted">In this order: guardrails go on before allows and come off after them.</p><ol>'
                   + "".join(f"<li>{_e(m['change'])} <code>{_e(m['policy'])}</code> "
                             f"{'to' if m['change'] == 'attach' else 'from'} <code>{_e(m['target'])}</code></li>"
                             for m in moves) + "</ol>")
    out.append("</div></section>")
    return "".join(out)


def _review(files: dict) -> str:
    review = files.get("review")
    out = ['<section id="review"><h2>Release review</h2>']
    if not review:
        out.append('<p class="muted">Review hasn\'t run on this run.</p></section>')
        return "".join(out)
    counts = review.get("counts", {})
    out.append('<div class="tiles">' + _tile(DECISIONS.get(review.get("decision"), review.get("decision")), "decision")
               + _tile(review.get("residual_risk") or "none", "residual risk")
               + _tile(len(review.get("blockers", [])), "blockers")
               + _tile(counts.get("needs acceptance", 0), "doubts need a person")
               + _tile(counts.get("accepted", 0) + counts.get("auto-accepted", 0), "doubts accepted",
                       f"auto-accept ceiling {review.get('auto_accept_ceiling') or 'none'}") + "</div>")
    if review.get("blockers"):
        out.append('<div class="card bad-edge"><h3>Blockers</h3><ul>' + "".join(
            f"<li><b>{_e(b.get('check'))}</b> <code>{_e(b.get('subject'))}</code>: {_e(b.get('detail'))}</li>"
            for b in review["blockers"]) + "</ul></div>")
    open_ = [d for d in review.get("doubts", []) if d.get("status") == "needs acceptance"]
    if open_:
        out.append('<div class="table-wrap"><table><thead><tr><th>Doubt</th><th>Risk</th><th>What a person accepts</th>'
                   "</tr></thead><tbody>" + "".join(
                       f'<tr><th scope="row"><code>{_e(d.get("id"))}</code><div class="muted">{_e(d.get("detail"))}</div>'
                       f'</th><td>{_chip(d.get("risk"), "risk-" + str(d.get("risk", "")).lower())}</td>'
                       f'<td>{_e(d.get("accept_means"))}</td></tr>' for d in open_) + "</tbody></table></div>")
    out.append("</section>")
    return "".join(out)


def _sources(files: dict) -> str:
    profile = files.get("capability-profile") or {}
    verification = files.get("verification") or {}
    review = files.get("review") or {}
    items = [f"<li>{_e(s.get('source'))}: {_link(s.get('url', ''))} (retrieved {_e(s.get('retrieved'))})</li>"
             for s in profile.get("sources", [])]
    nist = (files["selection"].get("nist_catalog") or {})
    if nist:
        items.append(f"<li>NIST SP 800-53 catalog {_e(nist.get('version'))} (pinned index)</li>")
    for label, value in (("Policy set SHA-256", review.get("policy_set_sha256") or verification.get("policy_set_sha256")),
                         ("Security spec SHA-256", (verification.get("spec") or {}).get("sha256"))):
        if value:
            items.append(f"<li>{_e(label)}: <code>{_e(value)}</code></li>")
    return f'<section id="sources"><h2>Sources and integrity</h2><ul class="sources">{"".join(items)}</ul></section>'


CSS = """
:root{--bg:#f7f7f5;--surface:#fff;--text:#1d1f23;--muted:#5d6470;--border:#dcdfe4;--accent:#2e5bba;
--ok:#1f7a4d;--ok-bg:#e3f3ea;--warn:#8a5a00;--warn-bg:#fbf0d9;--bad:#a23030;--bad-bg:#f8e2e2;
--plan:#5b47a8;--plan-bg:#ebe7f7;--det:#1f6a8a;--det-bg:#e0eff5;--gap:#7a7f88;--gap-bg:#eceef1;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#15171a;--surface:#1e2125;--text:#e6e8eb;--muted:#9aa1ab;
--border:#33373d;--accent:#8fb0f0;--ok:#7fd1a5;--ok-bg:#1d3a2b;--warn:#f0c46a;--warn-bg:#3d311a;--bad:#f09a9a;
--bad-bg:#432325;--plan:#b9a8f2;--plan-bg:#2e2747;--det:#8fcfe8;--det-bg:#1b3440;--gap:#a3a8b0;--gap-bg:#2b2e33;
color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
header.top{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-end;justify-content:space-between;
border-bottom:1px solid var(--border);padding-bottom:16px}
h1{margin:0;font-size:28px;line-height:1.2}h2{font-size:20px;margin:40px 0 12px}h3{font-size:15px;margin:0 0 8px}
h4{margin:6px 0 8px;font-size:15px}.category{margin:28px 0 10px;font-size:16px}.category .muted{font-weight:400;font-size:14px}
.muted{color:var(--muted)}code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
a{color:var(--accent)}nav{display:flex;gap:14px;flex-wrap:wrap;font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.tile,.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .value{font-size:24px;font-weight:650}.tile .label{color:var(--muted);font-size:13px}.tile .note{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,320px),1fr));gap:12px;align-items:start}
.flow{columns:3 320px;column-gap:12px}.flow>.card{break-inside:avoid;margin:0 0 12px;display:block}
.grid.two{grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr))}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;
background:var(--gap-bg);color:var(--gap);margin:2px 2px 2px 0}.chip.small{font-size:11px}.chip.plain{font-weight:500;color:var(--text)}
.ok,.cov-prevented,.st-generated{background:var(--ok-bg)!important;color:var(--ok)!important}
.bad,.risk-high,.risk-critical{background:var(--bad-bg)!important;color:var(--bad)!important}
.risk-medium,.st-pending,.st-not_deployed{background:var(--warn-bg)!important;color:var(--warn)!important}
.cov-plan-time{background:var(--plan-bg)!important;color:var(--plan)!important}
.cov-detected{background:var(--det-bg)!important;color:var(--det)!important}
.cov-gap{background:var(--bad-bg)!important;color:var(--bad)!important}
.threat{border-left-width:4px}.cov-prevented-edge{border-left-color:var(--ok)}.cov-plan-time-edge{border-left-color:var(--plan)}
.cov-detected-edge{border-left-color:var(--det)}.cov-gap-edge,.bad-edge{border-left:4px solid var(--bad)}
.threat header{display:block}.controls{list-style:none;margin:0;padding:0}.controls li{padding:6px 0;border-top:1px solid var(--border)}
.risk{margin-top:8px;padding:8px 10px;border-radius:8px;background:var(--warn-bg);font-size:13px}
.blind{margin-top:8px;font-size:13px}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--gap-bg);margin:6px 0}
.seg{display:block;height:100%}.legend{list-style:none;display:flex;flex-wrap:wrap;gap:4px 16px;padding:0;margin:4px 0 8px;font-size:13px}
.dot{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.tier-read,.cov-prevented.dot,.seg.cov-prevented,.dot.cov-prevented{background:var(--ok)!important}
.tier-list{background:var(--det)}.tier-write{background:var(--warn)}.tier-tagging{background:var(--plan)}
.tier-permission-management{background:var(--bad)}
.seg.cov-plan-time,.dot.cov-plan-time{background:var(--plan)!important}.seg.cov-detected,.dot.cov-detected{background:var(--det)!important}
.seg.cov-gap,.dot.cov-gap{background:var(--bad)!important}
.meter{height:8px;border-radius:4px;background:var(--gap-bg);overflow:hidden}.meter span{display:block;height:100%;background:var(--accent)}
.meter.over span{background:var(--bad)}
dl{margin:0}dt{font-size:13px;color:var(--muted);margin-top:8px}dd{margin:2px 0 0}
.table-wrap{overflow-x:auto;margin-top:12px;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:8px 10px;border-top:1px solid var(--border);vertical-align:top}
thead th{border-top:0;color:var(--muted);font-weight:600;white-space:nowrap}tbody th{font-weight:500;min-width:220px}
.notes ul,.notes ol,.sources{margin:0;padding-left:18px}.notes{margin-top:12px}
footer{margin-top:48px;color:var(--muted);font-size:13px}
@media print{body{background:#fff}.card,.tile,.table-wrap{break-inside:avoid}}
"""


def render(files: dict) -> str:
    """The report for one run's files (see `load`)."""
    selection, generation = files["selection"], files["generation"]
    profile = files.get("capability-profile") or {}
    review = files.get("review") or {}
    verification = files.get("verification") or {}
    vectors = threats(files)
    service = profile.get("service") or generation.get("service")
    statuses = generation.get("controls", {})
    guardrails = sum(1 for s in statuses.values() for p in GUARDRAILS if s.get(p, {}).get("status") == "generated")
    proofs = verification.get("proofs", [])
    caught = sum(p.get("mutants", {}).get("caught", 0) for p in proofs)
    decision = review.get("decision")
    covered = sum(v["coverage"] != "gap" for v in vectors)
    title = f"{service} security report"
    body = [
        f'<header class="top"><div><div class="muted">Service onboarding report · {_e(selection.get("maturity_tier"))} · '
        f'criticality {_e(selection.get("criticality"))}</div><h1>{_e(service)}</h1></div>'
        f'<div>{_chip(DECISIONS.get(decision, decision), {"release": "ok", "hold": "risk-medium", "blocked": "bad"}.get(decision, ""))}'
        + (f'<div class="muted">Reviewed {_e(review["reviewed_on"])}</div>' if review.get("reviewed_on") else "")
        + "</div></header>",
        '<nav aria-label="Sections"><a href="#service">Service</a><a href="#threats">Threat vectors</a>'
        '<a href="#guardrails">Guardrails</a><a href="#placement">Placement</a><a href="#review">Review</a><a href="#sources">Sources</a></nav>',
        '<div class="tiles">'
        + _tile(len(files["controls"]), "controls selected", ", ".join(
            f"{v} {k}" for k, v in sorted((selection.get("counts") or {}).get("mode", {}).items())))
        + _tile(f"{covered}/{len(vectors)}", "threat vectors covered")
        + _tile(guardrails, "guardrail statements", f"{len(generation.get('policies') or {})} policies")
        + _tile(f"{sum(p.get('result') == 'pass' for p in proofs)}/{len(proofs)}" if proofs else "—", "statements proved",
                f"{caught} mutants caught" if proofs else "Verify hasn't run")
        + _tile(len(generation.get("detective_artifacts") or {}), "detective artifacts", "Config, EventBridge, Sentinel")
        + "</div>",
        _service(files), _threats(files, vectors), _guardrails(files), _placement(files), _review(files),
        _sources(files),
        f'<footer>Generated by onboard {_e(__version__)} from the run\'s files; it deploys nothing. '
        "Detective artifacts haven't run in AWS Config, EventBridge or Sentinel unless stated.</footer>",
    ]
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            '<meta name="referrer" content="no-referrer">'
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>"
            + "".join(body) + "</main></body></html>\n")
