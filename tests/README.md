# Offline validation

From the repository root, with Python 3.10 or newer:

```sh
python3 -m pip install -r tests/requirements.txt
python3 scripts/sync_rule_sets.py
python3 -m unittest discover -s tests -v
```

The default snapshot command only checks files. After intentionally editing the
Clash rule lists, run `python3 scripts/sync_rule_sets.py --write` and review both
snapshots' diffs. It preserves exact-domain, suffix and keyword match types,
collapses duplicates, and rejects malformed values, unsupported rule types and
duplicate YAML keys. Snapshot checks also reject duplicate JSON keys and
non-integer versions, which Python's ordinary JSON comparison can miss.
It never fetches a URL, reads a private config, or changes
the selection/routing groups. Other rule types need an explicit converter and
test change; they are never silently discarded. Snapshots remain manual local
files, with no background refresh.

To include engine checks on Linux, download the official **sing-box 1.14.3** and
**Mihomo v1.19.33** executables and set their absolute paths:

```sh
SING_BOX=/absolute/path/to/sing-box MIHOMO=/absolute/path/to/mihomo \
  python3 -m unittest discover -s tests -v
```

Without these variables the engine tests are explicitly skipped. CI requires
both, verifies the release archives' SHA-256 digests, and runs the same tests.
The version pins are compatibility baselines, not a request to upgrade devices.

The suite checks every source rule against its snapshot, malformed-rule failure
cases, group types and effective selection defaults, provider definitions,
exact private CIDRs with `no-resolve`, streaming/CN
priority, the hosts override, IPv4 DNS behavior and local-only inbounds. It
compares the official sing-box source and compiled-binary matchers against
classical-rule semantics for positive, negative, subdomain, uppercase and
label-boundary cases. Compiled files are temporary. Explicit `--format binary`
is required: this CLI defaults to source format even for a `.srs` filename.

Mihomo `-t` receives a temporary copy with documentation-only IP addresses and
synthetic credentials, plus local file providers instead of HTTP providers.
Missing node references are deliberately **not** patched in the fixture, so they
fail the test. Eight negative cases add each undefined extension node to each
affected group; a positive case defines all four nodes before adding them.
The `todo` node/host values in the tracked template are intentional setup
placeholders. The fixture substitutes those values and localizes existing
providers without recreating missing definitions or changing their behavior.
Mihomo `-t` validates configuration parsing and references; it does not test
runtime provider matching. Rule content is checked separately by the strict
converter and sing-box matcher comparison.

No test starts a proxy service, opens a listener, queries DNS, fetches a
subscription, or changes system networking. Passing checks do not prove proxy
credentials, server availability, actual connection success or client-injected
settings. Rule-order assertions protect the recorded policy; they are not live
end-to-end routing tests.

Pinned sing-box references:
[headless rule semantics](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/rule-set/headless-rule.md),
[route actions](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/route/rule_action.md),
[match CLI](https://github.com/SagerNet/sing-box/blob/v1.14.3/cmd/sing-box/cmd_rule_set_match.go),
[IP matching without an implicit lookup](https://github.com/SagerNet/sing-box/blob/v1.14.3/route/rule/rule_item_cidr.go).
