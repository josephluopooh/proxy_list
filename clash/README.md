# Clash / Mihomo

`clash_josephluo.yaml` is a personal **template**, checked with the official
[Mihomo v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33)
Linux amd64 release. It is not a ready-to-connect subscription.

Copy it to `config.local.yaml` (ignored by Git). Replace both nodes' server,
port, password or UUID placeholders, and set transport/TLS options required by
your nodes. Replace or remove the two company `hosts` entries containing `todo`;
they are intentional placeholders, not IP addresses. Keep credentials private.
Then check your private copy with `mihomo -t -f config.local.yaml`.

The active groups include only defined nodes `s1` and `s3`. The old `s2`, `s4`,
`s5` and `s801` names are retained in comments: define those proxies before
adding them to `auto_select` and `streaming_media`. Undefined active references
make Mihomo reject the whole configuration even after filling the other nodes.
All five group names, available defined-node choices and proxy-first defaults
are preserved. Failed proxy nodes do not automatically fall back to `DIRECT`.

Routing remains private IPv4 (`10/8`, `172.16/12`, `192.168/16`) to `DIRECT`
without DNS resolution, then `streaming_media`, then `CN`, then `final`. `CN`
is a curated list, not a geographic classification. The overlap
`apm-misaka.biliapi.net` follows `streaming_media`. Both rule providers continue
to use this repository's public files with a daily refresh interval.

No DNS upstream is set in the template. Mihomo v1.19.33 supplies built-in
defaults (`https://doh.pub/dns-query` and `tls://223.5.5.5:853`), with separate
bootstrap resolvers; clients may also inject DNS settings. This differs from
the sing-box template's explicit system resolver. The inherited
`experimental.ignore-resolve-fail` key is not recognized by this Mihomo version;
do not rely on it to suppress DNS errors. No DNS behavior is changed by this
review. Older Clash variants have not been validated.

The duplicate CloudFront exact rule and whitespace-containing
`disneyStreaming Media.com` suffix were removed. No replacement Disney domain
was inferred. All 77 unique valid streaming rules and 32 CN rules are retained.

For reproducible, credential-free checks and local snapshot updates, see
[validation](../tests/README.md).

Pinned implementation references:
[configuration defaults and DNS parsing](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/config/config.go),
[group reference validation](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outboundgroup/parser.go),
[suffix matching](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/rules/common/domain_suffix.go).
