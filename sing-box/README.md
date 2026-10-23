# sing-box

This is a credential-free counterpart to `../clash/clash_josephluo.yaml`,
validated with the official **sing-box 1.14.3** Windows amd64 release
(2026-10-09). It uses the current typed DNS servers, rule actions and source
rule-set format, without deprecated configuration fields.

## Setup

1. Install [sing-box 1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)
   or a compatible newer stable release. These instructions assume `sing-box`
   is on your PATH. In PowerShell, enter this directory and make a private copy:

   ```powershell
   Set-Location sing-box
   Copy-Item sing-box_josephluo.json config.local.json
   ```

2. In `config.local.json`, replace the `s1` Shadowsocks server, port and password,
   and the `s3` VMess server, port and UUID with your own values. The `.invalid`
   hostnames, port 443, replacement password and example UUID are placeholders,
   not usable nodes. Set any transport/TLS options required by your actual nodes.
   Keep TLS verification enabled. The local copy is ignored by Git; do not put
   credentials or private subscription URLs in the tracked template.

3. Check the edited configuration without starting a proxy:

   ```powershell
   sing-box check -c config.local.json
   ```

4. When ready to use it, stop any Clash instance occupying the same ports, then
   start it yourself with `sing-box run -c config.local.json`. Configure the
   application you want to proxy to use HTTP or SOCKS5 at `127.0.0.1:7890`.
   The profile has no TUN inbound and `set_system_proxy` is false. It does not
   change system proxy settings or routing. Keep this directory as the working
   directory so `rule-set/*.json` resolves correctly. Retain the sibling rule-set
   files when copying the profile; a single-file remote profile import is not
   sufficient for this local layout.

The local Clash-compatible API uses `127.0.0.1:17650`. An API-compatible client can
change selector choices; no dashboard download or API secret is embedded. You
can also edit each selector's `default` in the private copy before starting.
The profile starts in rule mode. The API's direct and global modes route through
`DIRECT` and `PROXY` respectively; the domain/IP policies below apply in rule
mode. Selections and mode are not persisted across restarts.

## Behavior carried over

| Clash setting | sing-box behavior |
| --- | --- |
| `mixed-port: 7890`, `allow-lan: false` | HTTP/SOCKS mixed inbound on `127.0.0.1:7890` |
| `log-level: info` | Info logging |
| `PROXY` | Selects `auto_select` |
| `auto_select` | Tests `s1` and `s3` every five minutes using the original gstatic URL |
| `CN` | `PROXY` or `DIRECT`, default `PROXY` |
| `streaming_media` | `PROXY`, `DIRECT`, `s1` or `s3`, default `PROXY` |
| `final` | `PROXY` or `DIRECT`, default `PROXY` |
| Private IPv4 rules | `10/8`, `172.16/12`, `192.168/16` go direct before domain rules |
| Rule order | `streaming_media`, then `CN`, then `final` |
| Shadowsocks `s1` | `aes-256-gcm`, TCP and UDP enabled |
| VMess `s3` | `auto`, AEAD (`alter_id: 0`), TCP only as in the source's omitted UDP option |

`CN` is the repository's curated domain list, not a GeoIP/geosite rule for all of
China. Its proxy-first default is intentional. An overlapping domain such as
`apm-misaka.biliapi.net` follows `streaming_media` before `CN`. IP range matching
does not trigger DNS resolution, preserving the original `no-resolve` intent.

## DNS and differences

- Internal DNS uses IPv4-only resolution; DNS-rule evaluation returns an empty
  successful answer for AAAA queries. The typed `hosts` server reads the platform
  hosts file and keeps `mtalk.google.com -> 108.177.125.188`. A targeted resolve
  action applies that explicit override even when the destination uses a proxy.
- The Clash file enables DNS but supplies no upstream resolver. This template
  explicitly uses the system resolver as its fallback; it does not invent DoH,
  fake-IP, DNS interception, or a China/global DNS split. Configure DNS separately
  if your existing client injects an upstream. DNS is internal: no standalone
  port-53 listener or system DNS setting is created.
- Other proxied hostnames remain domain names for the remote proxy to resolve.
  IPv4-only internal resolution does not constrain the remote proxy's DNS.
  Also, `default_domain_resolver: local` resolves direct destinations and proxy
  server names through the system DNS upstream, bypassing DNS routing rules.
  Automatic system-hosts handling is therefore not fully equivalent to Clash's
  `use-system-hosts`. To force another hosts mapping, add it to
  `hosts.predefined` (or the platform hosts file) and to the targeted `resolve`
  rule's `domain` list in your private copy. For a proxy server hostname, use its
  IP or explicitly set that node's `domain_resolver` to `hosts`. Do not broadly
  resolve every proxy destination locally: doing so would make proxy access
  depend on the local resolver.
- The company host entries contain `todo` instead of IP addresses in the source;
  they are intentionally omitted. Add real mappings privately if needed.
- The source lists `s2`, `s4`, `s5` and `s801` without defining them. Only the two
  defined node types are included. Add real outbounds first, then add their tags
  to `auto_select` and `streaming_media`. Failed proxy nodes never automatically
  fall back to `DIRECT`; direct access requires choosing it explicitly.
- Clash's `lazy` URL-test flag has no exact sing-box equivalent. The five-minute
  test interval is retained and sing-box's 30-minute idle timeout is explicit.
  Its default latency tolerance is unchanged.
- Rules are bundled local JSON snapshots instead of the source's daily HTTP rule
  providers. Update them alongside the Clash lists. There is no automatic remote
  refresh; this keeps the unpublished checkout usable without nonexistent remote
  paths and avoids downloads during checking. This profile does not read Clash
  YAML subscriptions or include a subscription converter.
- All 32 CN entries and 77 unique valid streaming entries are retained, including
  exact-domain, suffix and keyword matches. The duplicate
  `dmqdd6hw24ucf.cloudfront.net` is collapsed. The malformed source suffix
  `disneyStreaming Media.com` contains whitespace and is omitted without guessing
  a replacement. The Clash files themselves remain unchanged.
- `prefer-h3`, `ipv6-timeout` and `experimental.ignore-resolve-fail` have no direct
  field-for-field equivalent here. No HTTP/3 DNS transport or IPv6 fallback is
  configured. Ordinary proxy domain requests do not require local resolution;
  errors from an explicitly requested local resolve action are not ignored.

## Validation

From this directory, these commands only check/compile local files:

```powershell
sing-box version
sing-box check -c sing-box_josephluo.json
sing-box rule-set compile --output rule-set/CN.srs rule-set/CN.json
sing-box rule-set compile --output rule-set/streaming_media.srs rule-set/streaming_media.json
sing-box rule-set match rule-set/streaming_media.json apm-misaka.biliapi.net
sing-box rule-set match rule-set/CN.json apm-misaka.biliapi.net
```

The generated `.srs` files are ignored and are not needed by this source-format
configuration. Passing `check` confirms the schema and references, not credentials,
server reachability, DNS availability, or a successful proxy connection. The
implementation was checked without starting sing-box or contacting proxy nodes.
Offline verification compared every converted rule against the Clash source,
passed 309 source/binary rule-match checks and 12 routing-policy cases, and
verified that the original Clash file blobs were unchanged. These checks do not
replace a live connection test with your own node details.

Official references: [DNS](https://sing-box.sagernet.org/configuration/dns/),
[hosts](https://sing-box.sagernet.org/configuration/dns/server/hosts/),
[rule actions](https://sing-box.sagernet.org/configuration/route/rule_action/),
[rule sets](https://sing-box.sagernet.org/configuration/rule-set/),
[selectors](https://sing-box.sagernet.org/configuration/outbound/selector/),
[URL tests](https://sing-box.sagernet.org/configuration/outbound/urltest/).
