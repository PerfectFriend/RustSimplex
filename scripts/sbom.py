#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for smp-rs from Cargo.lock.

No external tooling required: the lockfile already pins every dependency
with its source and the sha256 of the .crate file, which is exactly what a
CycloneDX component needs.

    python3 scripts/sbom.py --output target/package/sbom.cdx.json
"""
import argparse
import datetime
import json
import pathlib
import re
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent


def parse_lock(text):
    packages = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "(.*)"', block, re.M)
        version = re.search(r'^version = "(.*)"', block, re.M)
        if not name or not version:
            continue
        source = re.search(r'^source = "(.*)"', block, re.M)
        checksum = re.search(r'^checksum = "(.*)"', block, re.M)
        license = re.search(r'^license = "(.*)"', block, re.M)
        packages.append(
            {
                "name": name.group(1),
                "version": version.group(1),
                "source": source.group(1) if source else None,
                "checksum": checksum.group(1) if checksum else None,
                "license": license.group(1) if license else None,
            }
        )
    return packages


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="target/package/sbom.cdx.json")
    args = ap.parse_args()

    cargo_toml = (ROOT / "Cargo.toml").read_text()
    root_version = re.search(r'^version = "(.*)"', cargo_toml, re.M).group(1)
    packages = parse_lock((ROOT / "Cargo.lock").read_text())

    components = []
    for p in packages:
        if p["name"] == "smp-rs":
            continue
        c = {
            "type": "library",
            "name": p["name"],
            "version": p["version"],
            "purl": f"pkg:cargo/{p['name']}@{p['version']}",
            "properties": [
                {"name": "smp-rs:cargo-source", "value": p["source"] or "local"},
            ],
        }
        if p["checksum"]:
            c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
        if p["license"]:
            c["licenses"] = [{"expression": p["license"]}]
        components.append(c)
    components.sort(key=lambda c: c["name"])

    root = {
        "type": "library",
        "name": "smp-rs",
        "version": root_version,
        "purl": f"pkg:cargo/smp-rs@{root_version}",
        "bom-ref": f"pkg:cargo/smp-rs@{root_version}",
    }

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": [{"vendor": "smp-rs", "name": "scripts/sbom.py"}],
            "component": root,
        },
        "components": components,
        "dependencies": [
            {
                "ref": root["bom-ref"],
                "dependsOn": [c["purl"] for c in components],
            }
        ],
    }

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"SBOM: {out} ({len(components)} components, root smp-rs {root_version})")


if __name__ == "__main__":
    main()
