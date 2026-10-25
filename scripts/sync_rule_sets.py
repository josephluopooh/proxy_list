#!/usr/bin/env python3
"""Check or explicitly regenerate the local sing-box snapshots; never fetch URLs."""

import argparse
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("CN", "streaming_media")
FIELDS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
}


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate mapping keys instead of silently losing configuration."""


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor("tag:yaml.org,2002:map", unique_mapping)


def read_yaml(path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_snapshot(path):
    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)
    # Python considers 5.0 equal to 5, but sing-box requires an integer version.
    if not isinstance(document, dict) or type(document.get("version")) is not int:
        raise ValueError(f"{path}: snapshot version must be an integer")
    return document


def convert(document):
    """Convert only the repository's domain-rule subset, failing on unknown rules."""
    if not isinstance(document, dict) or set(document) != {"payload"}:
        raise ValueError("expected a mapping containing only payload")
    if not isinstance(document["payload"], list) or not document["payload"]:
        raise ValueError("payload must be a nonempty list")
    rule = {}
    for index, entry in enumerate(document["payload"], 1):
        if not isinstance(entry, str) or len(entry.split(",")) != 2:
            raise ValueError(f"payload[{index}]: expected TYPE,value")
        kind, value = entry.split(",")
        if kind not in FIELDS:
            raise ValueError(f"payload[{index}]: unsupported rule type {kind}")
        value = value.lower()
        if kind == "DOMAIN-KEYWORD":
            valid = re.fullmatch(r"[a-z0-9_.-]+", value)
        else:
            valid = len(value) <= 253 and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.split(".")
            )
        if not valid:
            raise ValueError(f"payload[{index}]: invalid {kind} value {value!r}")
        values = rule.setdefault(FIELDS[kind], [])
        if value not in values:
            values.append(value)
    # These domain fields are ORed by sing-box, preserving classical rule semantics.
    return {"version": 5, "rules": [rule]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate snapshots locally")
    args = parser.parse_args()
    try:
        # Validate every source before writing any snapshot.
        snapshots = {name: convert(read_yaml(ROOT / "clash" / f"{name}.yaml")) for name in NAMES}
        stale = []
        for name, expected in snapshots.items():
            path = ROOT / "sing-box" / "rule-set" / f"{name}.json"
            if args.write:
                path.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
            elif not path.exists() or read_snapshot(path) != expected:
                stale.append(name)
        if stale:
            raise ValueError(f"stale snapshots: {', '.join(stale)}; run with --write and review the diff")
    except (ValueError, OSError, yaml.YAMLError) as error:
        print(error, file=sys.stderr)
        return 1
    print("Rule snapshots " + ("updated" if args.write else "match Clash sources"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
