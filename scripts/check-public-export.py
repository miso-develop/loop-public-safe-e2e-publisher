#!/usr/bin/env python3
"""Provider CI fixture, not an origin attestation or independent review."""
import hashlib
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_MANIFEST_SHA256 = "77561f8c425605c39485a568d863bcd31bb1fdced79a52fc6cbe3b7174248411"
EXPECTED_EXPORT_ID = "b98d4cd9201dcf0f7425dc889d89968c7de869c7971269da53480fe457c8fe4c"
APPROVED = [
    ("governance/engineering-review.md", "9c5d467f81c96364ec596d81b97b360cb8059c8e91f5cd0fcb31ec32bdf11378"),
    ("governance/security-review.md", "365c4cfe8c288c511a6689c20f24ddf6f3b077333bb2fa3a908b8ceac2ceaff5"),
]
CAPS = {"canonicalVerifier": False, "consumerGates": "repository-owned", "assurance": "content-integrity-only"}
ALLOW_TRACKED = {
    "README.md", ".github/workflows/public-export-ci.yml", "scripts/check-public-export.py",
    "manifest.json", *(p for p, _ in APPROVED),
}
sha256 = lambda x: hashlib.sha256(x).hexdigest()
def fail(message):
    raise SystemExit("PUBLIC_EXPORT_CI_FAIL: " + message)
def object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate manifest key")
        result[key] = value
    return result
def canonical(obj):
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
def main():
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    if tracked != ALLOW_TRACKED:
        fail("unexpected public tracked paths")
    modes = dict((line.split()[3], line.split()[0]) for line in
                 subprocess.check_output(["git", "ls-files", "-s"], cwd=ROOT, text=True).splitlines())
    if any(modes.get(path) != "100644" for path, _ in APPROVED):
        fail("governance blob is not regular mode 100644")
    manifest_bytes = (ROOT / "manifest.json").read_bytes()
    if sha256(manifest_bytes) != EXPECTED_MANIFEST_SHA256:
        fail("out-of-band approved digest mismatch")
    try:
        data = json.loads(manifest_bytes, object_pairs_hook=object_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        fail("invalid manifest JSON")
    if not isinstance(data, dict):
        fail("manifest is not a map")
    expected_keys = {"schemaVersion","profile","profileVersion","exportId","capabilities","files"}
    if set(data) != expected_keys or data["schemaVersion"] != 2 or data["profileVersion"] != 2:
        fail("schema mismatch")
    if data["profile"] != "loop-public-safe-governance" or data["capabilities"] != CAPS:
        fail("profile/capability mismatch")
    rows = [{"path": path, "sha256": digest, "operation": "upsert"} for path, digest in APPROVED]
    if data["files"] != rows or data["exportId"] != EXPECTED_EXPORT_ID:
        fail("manifest rows or export identity mismatch")
    if canonical(data) != manifest_bytes:
        fail("manifest not canonical")
    payload = {"schemaVersion":2,"profile":"loop-public-safe-governance","profileVersion":2,
               "capabilities":CAPS,"files":rows}
    calculated_export_id = sha256(("loop-public-safe-v2\n" +
                                  json.dumps(payload, ensure_ascii=False, separators=(",", ":")) +
                                  "\n").encode())
    if calculated_export_id != EXPECTED_EXPORT_ID:
        fail("deterministic export identity mismatch")
    for path, digest in APPROVED:
        blob = (ROOT / path).read_bytes()
        if not 0 < len(blob) <= 16384 or sha256(blob) != digest:
            fail("file byte mismatch: " + path)
        if any(b not in (9, 10) and not (32 <= b <= 126) for b in blob):
            fail("non-ASCII text in public governance file")
        if re.search(rb"https?://|github\.com|git@|ghp_|github_pat_|-----BEGIN|[a-f0-9]{40}|[a-z]:\\|/(?:home|users|tmp)/", blob, re.I):
            fail("public content privacy pattern")
    print("PUBLIC_EXPORT_CI=PASS: approved bytes, paths, modes, digest, v2 identity")
if __name__ == "__main__":
    main()
