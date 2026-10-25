"""Offline policy and parser regressions; optional pinned-engine checks use no listeners."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from sync_rule_sets import NAMES, ROOT, UniqueLoader, convert, read_yaml
import yaml


CLASH = ROOT / "clash" / "clash_josephluo.yaml"
SING = ROOT / "sing-box" / "sing-box_josephluo.json"
GROUPS = {
    "PROXY": ["auto_select"],
    "auto_select": ["s1", "s3"],
    "CN": ["PROXY", "DIRECT"],
    "streaming_media": ["PROXY", "DIRECT", "s1", "s3"],
    "final": ["PROXY", "DIRECT"],
}
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(f"{args[0]} exited {result.returncode}: {result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def source_matches(payload, host):
    """Independent classical-rule oracle, including overlapping entries."""
    host = host.lower()
    for entry in payload:
        kind, value = entry.lower().split(",")
        if kind == "domain" and host == value:
            return True
        if kind == "domain-suffix" and (host == value or host.endswith("." + value)):
            return True
        if kind == "domain-keyword" and value in host:
            return True
    return False


class RuleConversionTests(unittest.TestCase):
    def test_snapshots_preserve_every_rule(self):
        for name in NAMES:
            with self.subTest(name=name):
                source = read_yaml(ROOT / "clash" / f"{name}.yaml")
                target = json.loads((ROOT / "sing-box" / "rule-set" / f"{name}.json").read_text())
                self.assertEqual(convert(source), target)

    def test_reject_malformed_or_unsupported_rules(self):
        for entry in ["DOMAIN-SUFFIX,disneyStreaming Media.com", "DOMAIN,", "DOMAIN,-bad.com",
                      "DOMAIN,foo..com", "DOMAIN,*.example.com", "DOMAIN,example.com,PROXY",
                      "DOMAIN,https://example.com", "IP-CIDR,10.0.0.0/8", "DOMAIN-KEYWORD, ", None]:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                convert({"payload": [entry]})

    def test_reject_wrong_document_shape(self):
        for document in [None, [], {}, {"payload": []}, {"payload": "DOMAIN,a.com"},
                         {"payload": ["DOMAIN,a.com"], "unknown": True}]:
            with self.subTest(document=document), self.assertRaises(ValueError):
                convert(document)
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            yaml.load("payload: [DOMAIN,a.com]\npayload: []", Loader=UniqueLoader)

    def test_duplicates_and_match_types(self):
        result = convert({"payload": ["DOMAIN,Example.COM", "DOMAIN,example.com",
                                      "DOMAIN-SUFFIX,example.com", "DOMAIN-KEYWORD,-example-com"]})
        self.assertEqual(result["rules"], [{"domain": ["example.com"],
                         "domain_suffix": ["example.com"], "domain_keyword": ["-example-com"]}])

    def test_update_command_checks_drift_and_validates_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            for child in ["scripts", "clash", "sing-box/rule-set"]:
                (tmp / child).mkdir(parents=True, exist_ok=True)
            script = tmp / "scripts/sync_rule_sets.py"
            shutil.copyfile(ROOT / "scripts/sync_rule_sets.py", script)
            for name in NAMES:
                shutil.copyfile(ROOT / "clash" / f"{name}.yaml", tmp / "clash" / f"{name}.yaml")
                (tmp / "sing-box/rule-set" / f"{name}.json").write_text("{}")
            with self.assertRaisesRegex(AssertionError, "stale snapshots"):
                run(sys.executable, str(script))
            self.assertEqual((tmp / "sing-box/rule-set/CN.json").read_text(), "{}")
            run(sys.executable, str(script), "--write")
            run(sys.executable, str(script))
            cn_snapshot = tmp / "sing-box/rule-set/CN.json"
            before = cn_snapshot.read_bytes()
            with (tmp / "clash/CN.yaml").open("a") as source:
                source.write("\n- DOMAIN,new.example.invalid\n")
            with (tmp / "clash/streaming_media.yaml").open("a") as source:
                source.write("\n- DOMAIN-SUFFIX,invalid domain\n")
            with self.assertRaisesRegex(AssertionError, "invalid DOMAIN-SUFFIX"):
                run(sys.executable, str(script), "--write")
            self.assertEqual(cn_snapshot.read_bytes(), before)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.clash = read_yaml(CLASH)
        self.sing = json.loads(SING.read_text())

    def test_selection_groups_and_defaults(self):
        self.assertEqual({g["name"]: g["proxies"] for g in self.clash["proxy-groups"]}, GROUPS)
        available = {p["name"] for p in self.clash["proxies"]} | set(GROUPS) | {"DIRECT"}
        for choices in GROUPS.values():
            self.assertTrue(set(choices) <= available)
        groups = {g["tag"]: g for g in self.sing["outbounds"] if "outbounds" in g}
        self.assertEqual({tag: g["outbounds"] for tag, g in groups.items()}, GROUPS)
        for tag, group in groups.items():
            if group["type"] == "selector":
                self.assertEqual(group["default"], GROUPS[tag][0])
        self.assertEqual(groups["auto_select"]["interval"], "5m")
        self.assertEqual(self.clash["proxy-groups"][1]["interval"], 300)
        self.assertEqual(groups["auto_select"]["url"], "http://www.gstatic.com/generate_204")
        self.assertEqual(self.clash["proxy-groups"][1]["url"], groups["auto_select"]["url"])
        nodes = {node["tag"]: node for node in self.sing["outbounds"]}
        self.assertEqual(nodes["s1"]["method"], "aes-256-gcm")
        self.assertEqual(nodes["s3"]["network"], "tcp")
        self.assertEqual(nodes["s3"]["alter_id"], 0)

    def test_routing_order_and_no_implicit_resolution(self):
        self.assertEqual(self.clash["rules"], [f"IP-CIDR,{net},DIRECT,no-resolve" for net in PRIVATE] +
                         ["RULE-SET,streaming_media,streaming_media", "RULE-SET,CN,CN", "MATCH,final"])
        self.assertEqual(self.sing["route"]["rules"], [
            {"domain": ["mtalk.google.com"], "action": "resolve", "server": "hosts", "strategy": "ipv4_only"},
            {"clash_mode": "direct", "action": "route", "outbound": "DIRECT"},
            {"clash_mode": "global", "action": "route", "outbound": "PROXY"},
            {"ip_cidr": PRIVATE, "action": "route", "outbound": "DIRECT"},
            {"rule_set": ["streaming_media"], "action": "route", "outbound": "streaming_media"},
            {"rule_set": ["CN"], "action": "route", "outbound": "CN"},
        ])
        self.assertEqual(self.sing["route"]["final"], "final")
        self.assertEqual(self.sing["experimental"]["clash_api"]["default_mode"], "rule")
        for provider in self.sing["route"]["rule_set"]:
            self.assertEqual(provider, {"type": "local", "tag": provider["tag"],
                             "format": "source", "path": f"rule-set/{provider['tag']}.json"})

    def test_exact_suffix_keyword_and_overlap_policy(self):
        sources = {name: read_yaml(ROOT / "clash" / f"{name}.yaml")["payload"] for name in NAMES}
        cases = {
            "apm-misaka.biliapi.net": "streaming_media", "other.biliapi.net": "CN",
            "paypal.com": "CN", "www.paypal.com": "CN", "notpaypal.com": "final",
            "paypal.com.invalid": "final", "gs-loc-cn.apple.com": "CN",
            "sub.gs-loc-cn.apple.com": "final", "cdn.netflix.com": "streaming_media",
            "www.amazon.com": "streaming_media", "sub.www.amazon.com": "final",
            "prefix-spotify-com.example.invalid": "streaming_media", "203.0.113.1": "final",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                matched = next((name for name in ["streaming_media", "CN"]
                                if source_matches(sources[name], host)), "final")
                self.assertEqual(matched, expected)

    def test_hosts_ipv4_and_local_inbound(self):
        self.assertFalse(self.clash["allow-lan"])
        self.assertFalse(self.clash["dns"]["ipv6"])
        dns = self.sing["dns"]
        self.assertEqual(dns["strategy"], "ipv4_only")
        self.assertEqual(dns["rules"][0], {"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"})
        self.assertEqual(dns["servers"][0]["predefined"]["mtalk.google.com"],
                         [self.clash["hosts"]["mtalk.google.com"]])
        self.assertEqual(self.sing["inbounds"], [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                         "listen_port": 7890, "set_system_proxy": False}])


@unittest.skipUnless(os.environ.get("MIHOMO"), "set MIHOMO to run pinned-engine validation")
class MihomoTests(unittest.TestCase):
    def test_synthetic_configuration(self):
        binary = str(Path(os.environ["MIHOMO"]).resolve())
        self.assertIn("v1.19.33 ", run(binary, "-v"))
        config = copy.deepcopy(read_yaml(CLASH))
        # Replace only documented credential/host placeholders, never missing groups.
        for node in config["proxies"]:
            node["server"], node["port"] = "192.0.2.1", 443
            if "password" in node:
                node["password"] = "synthetic-test-password"
            if "uuid" in node:
                node["uuid"] = "00000000-0000-4000-8000-000000000000"
        for host in ["gerrit.company", "jira.company"]:
            config["hosts"][host] = "192.0.2.2"
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            for name in NAMES:
                shutil.copyfile(ROOT / "clash" / f"{name}.yaml", tmp / f"{name}.yaml")
                config["rule-providers"][name] = {"type": "file", "behavior": "classical", "path": f"{name}.yaml"}
            path = tmp / "config.yaml"
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            self.assertIn("test is successful", run(binary, "-t", "-d", directory, "-f", str(path), cwd=tmp))


@unittest.skipUnless(os.environ.get("SING_BOX"), "set SING_BOX to run pinned-engine validation")
class SingBoxTests(unittest.TestCase):
    def test_schema_and_source_binary_matches(self):
        binary = str(Path(os.environ["SING_BOX"]).resolve())
        self.assertIn("sing-box version 1.14.3\n", run(binary, "version"))
        run(binary, "check", "-c", SING.name, cwd=SING.parent)
        count = 0
        with tempfile.TemporaryDirectory() as directory:
            for name in NAMES:
                source = ROOT / "sing-box" / "rule-set" / f"{name}.json"
                compiled = Path(directory) / f"{name}.srs"
                run(binary, "rule-set", "compile", "--output", str(compiled), str(source))
                payload = read_yaml(ROOT / "clash" / f"{name}.yaml")["payload"]
                hosts = {"unmatched.example.invalid", "203.0.113.1", "apm-misaka.biliapi.net"}
                for entry in payload:
                    _, value = entry.split(",")
                    hosts.update([value, value.upper(), "sub." + value, "not" + value, value + ".invalid"])
                for host in sorted(hosts):
                    expected = source_matches(payload, host)
                    for path, fmt in [(source, "source"), (compiled, "binary")]:
                        with self.subTest(rule_set=name, host=host, format=fmt):
                            output = run(binary, "rule-set", "match", "--format", fmt, "--", str(path), host)
                            self.assertEqual("match rules.[" in output, expected)
                            count += 1
        print(f"Verified {count} source/binary rule matches against Clash semantics")


if __name__ == "__main__":
    unittest.main()
