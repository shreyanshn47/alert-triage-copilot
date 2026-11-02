"""Turn ATT&CK STIX and SigmaHQ rules into text chunks (no embeddings here).

Scope: the six techniques in PLAN.md with all their sub-techniques, plus a few neighbours that
look similar, so retrieval has to discriminate and not just find the only candidate.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

FAMILIES = ("T1059", "T1003", "T1021", "T1053", "T1547", "T1110")
NEIGHBOURS = {
    "T1569.002",  # service execution (psexec, smbexec)
    "T1543.003",  # create or modify a Windows service
    "T1218.011",  # rundll32 proxy execution (comsvcs MiniDump)
    "T1078",  # valid accounts
    "T1558.003",  # kerberoasting
    "T1135",  # network share discovery
    "T1036",  # masquerading
    "T1204.002",  # user execution: malicious file
}
MAX_CHUNK_CHARS = 900
MAX_SIGMA_CHARS = 1600


@dataclass
class Chunk:
    source: str  # 'attack' | 'sigma'
    ref: str  # technique id, or Sigma rule title
    technique_ids: list[str]
    chunk_index: int
    content: str
    tenant_id: str = "public"
    extra: dict = field(default_factory=dict)


def in_scope(technique_id: str) -> bool:
    return technique_id in NEIGHBOURS or technique_id.split(".")[0] in FAMILIES


def clean_markdown(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)  # ATT&CK citation markers
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # [label](url) -> label
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def split_paragraphs(text: str, limit: int = MAX_CHUNK_CHARS) -> list[str]:
    """Pack paragraphs into pieces of at most `limit` characters (one long paragraph stays whole)."""
    pieces: list[str] = []
    current = ""
    for para in (p.strip() for p in text.split("\n\n")):
        if not para:
            continue
        if current and len(current) + len(para) + 2 > limit:
            pieces.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        pieces.append(current)
    return pieces


def load_attack(path: Path) -> list[Chunk]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    chunks: list[Chunk] = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ref is None or not in_scope(ref["external_id"]):
            continue
        tid, name = ref["external_id"], obj["name"]
        tactics = ", ".join(p["phase_name"] for p in obj.get("kill_chain_phases", []))
        header = f"{tid} {name} (MITRE ATT&CK technique; tactics: {tactics})."
        for i, piece in enumerate(split_paragraphs(clean_markdown(obj.get("description", "")))):
            chunks.append(Chunk("attack", tid, [tid], i, f"{header}\n{piece}"))
    return sorted(chunks, key=lambda c: (c.ref, c.chunk_index))


def _sigma_techniques(tags: list) -> list[str]:
    found = []
    for tag in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
        if m:
            found.append(m.group(1).upper())
    return found


def load_sigma(root: Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted((root / "rules" / "windows").rglob("*.yml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError, OSError):
            continue
        if not isinstance(rule, dict) or rule.get("status") in {"deprecated", "unsupported"}:
            continue
        techniques = [t for t in _sigma_techniques(rule.get("tags", [])) if in_scope(t)]
        if not techniques or not rule.get("title"):
            continue
        logsource = rule.get("logsource") or {}
        detection = yaml.safe_dump(rule.get("detection") or {}, default_flow_style=True, width=1000)
        text = "\n".join([
            f"Sigma detection rule: {rule['title']}",
            f"Techniques: {', '.join(techniques)}",
            f"Description: {clean_markdown(str(rule.get('description', '')))}",
            f"Log source: {', '.join(f'{k}={v}' for k, v in logsource.items())}",
            f"Detection logic: {detection.strip()}",
            f"Known false positives: {'; '.join(map(str, rule.get('falsepositives') or []))}",
            f"Severity: {rule.get('level', 'unknown')}",
        ])
        rel_path = str(path.relative_to(root)).replace("\\", "/")
        # DRL 1.1 requires keeping the rule author and a link wherever a rule match is reported.
        url = f"https://github.com/SigmaHQ/sigma/blob/master/{rel_path}"
        attribution = f"\nAuthor: {rule.get('author', 'unknown')}\nSource: {url} (Detection Rule License 1.1)"
        chunks.append(Chunk("sigma", str(rule["title"]), techniques, 0,
                            text[:MAX_SIGMA_CHARS] + attribution, extra={"path": rel_path}))
    # Titles are not guaranteed unique; keep the first of each so (source, ref, index) stays unique.
    seen: set[str] = set()
    unique = []
    for c in chunks:
        if c.ref not in seen:
            seen.add(c.ref)
            unique.append(c)
    return unique
