# nftables migration: deviations, decisions and open points

Working notes for the ebtables/iptables -> nftables port. These record where
the nftables ruleset is *not* a literal translation of the ebtables one, and
why. Intended for review of the migration; can be dropped before merge.

The pre-port originals are on `main` under `package/gluon-ebtables*/` and
`package/gluon-iptables-clamp-mss-to-pmtu/`, and are the reference for every
comparison below.

## Verifying the ruleset offline

The generator can be run without a node. Copy every rule file into a
simulated `/lib/gluon/nftables`, run `300-nftables` against Lua 5.1 with
stubs for `simple-uci`, `posix.glob`, `gluon.site` and `gluon.client_bridge`,
then check the result with `nft -c -f`. Everything below marked "verified"
was checked this way against nft 1.1.3.

Note that `nft -c` validates syntax and semantics of the ruleset, but says
nothing about whether a rule *matches the traffic it should*. The behavioural
claims still need a real node.

## Behavioural deviations from the ebtables ruleset

### Gratuitous ARP in the bridge loop avoidance rules

`gluon-nftables-filter-multicast`, `110-mcast-allow-arp.lua`.

The ebtables rules were:

    MULTICAST_OUT -p ARP --arp-opcode Reply --arp-gratuitous \
        --arp-mac-dst ff:43:05:00:00:00/ff:ff:ff:fc:00:00 -j RETURN
    MULTICAST_OUT -p ARP --arp-opcode Reply --arp-gratuitous \
        --arp-mac-dst ff:43:05:05:00:00/ff:ff:ff:ff:00:00 -j RETURN

`--arp-gratuitous` matches frames whose ARP sender and target protocol
addresses are equal. nftables cannot compare two packet fields against each
other - there is no `arp gratuitous` keyword and no payload-to-payload
comparison - so the condition has no equivalent and was dropped:

    arp operation reply arp daddr ether & ff:ff:ff:fc:00:00 == ff:43:05:00:00:00 return
    arp operation reply arp daddr ether & ff:ff:ff:ff:00:00 == ff:43:05:05:00:00 return

The rules are therefore slightly more permissive than before: a non-gratuitous
ARP reply addressed to a batman-adv claim address now returns as well. The
alternative - approximating the condition with `arp saddr ip 0.0.0.0` - would
have been *more* restrictive than the original and would silently drop
legitimate bridge loop avoidance frames, which is the worse failure mode.
The `ff:43:05:xx` destination is specific enough that over-matching is not a
practical concern.

Note the match is on the ARP payload target hardware address
(`arp daddr ether`, ebtables' `--arp-mac-dst`), not on the ethernet
destination address.

### Chain policies

ebtables chains have a policy; regular nftables chains do not - they always
fall through at their end. A policy other than RETURN is emitted as a
terminal rule appended after all rules of the chain, which is equivalent as
long as nothing appends to the chain afterwards. `bridge_chain()` takes the
policy as its second argument.

This is what `gluon-nftables-source-filter` relies on: its chain had policy
DROP, and without this the package filtered nothing at all.

### The ebtables nat table

The ebtables ruleset used two tables, `filter` and `nat`. On bridges these do
not differ in capability, only in when they run: the kernel registers the nat
table at different netfilter priorities. `gluon-ebtables` used this so that
IGMP/MLD could be dropped in nat PREROUTING, before any filter rule sees the
frame.

Everything now lives in a single `table bridge gluon`. The ordering is
reproduced by a second set of base chains registered at the priorities the
kernel uses for the ebtables nat table (`dstnat`, `out`, `srcnat`).
`bridge_chain()` and `bridge_rule()` take the ebtables table name as an
optional last argument. As OUTPUT exists in both tables, the nat base chains
are prefixed `nat_` in the generated ruleset.

Nuance not reproduced: ebtables registers filter OUTPUT at
`NF_BR_PRI_FILTER_OTHER` (200), while nft's `filter` keyword is -200 - the
same value `ebtables-nft` uses. Our filter OUTPUT therefore runs *before* nat
OUTPUT (100) rather than after it. Nothing currently places rules in nat
OUTPUT, so this has no effect today, but it would matter if something did.

### `-d Multicast`

ebtables' `-d Multicast` matches any destination MAC with the group bit set,
which includes broadcast. It is translated as a mask match:

    ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00

`meta pkttype multicast` would have been the obvious choice but is wrong: it
excludes broadcast, and `pkt_type` is not set in the OUTPUT hook. Verified.

### Mesh VPN DNS redirection

`gluon-mesh-vpn-core`. The original was an iptables rule in the nat OUTPUT
chain; it matches on the group of the sending socket and on the outgoing
interface, neither of which is known in the prerouting hook where the
migration had put it.

fw4 provides nat chains for prerouting (`dstnat`) and postrouting (`srcnat`)
only, so the include ships an output hooked chain of its own at priority -100,
the priority iptables used for its nat OUTPUT chain.

`DNAT --to-destination :54` became `redirect to :54`, which is equivalent
here as the destination is already 127.0.0.1.

`meta skgid "gluon-mesh-vpn"` is resolved by name when the ruleset is loaded;
the group is created by the package's Makefile as gid 800. Using the numeric
gid would be more robust against load ordering, but the name matches what the
iptables rule did.

### MSS clamping

The include position was `chain-prepend`, which fw4 does not know, so the
include was rejected outright and no clamping happened. It is now `chain-pre`,
matching the sibling include in `gluon-mesh-vpn-core`. The iptables original
appended (`-A FORWARD`), i.e. `chain-post`; the rule is non-terminal, so the
difference has no practical effect.

### ARP limiter resynchronisation

`gluon-nftables-limit-arp`. The daemon's sets live in `table bridge gluon`,
which every firewall reload flushes and recreates, while the daemon's address
stores still believed every address to be present - so no address was ever
added again and the rate limit stopped applying.

nftables requires a set in the same table as the rules referencing it, so the
sets cannot be kept out of the flush. The reload.d hooks only cover
`gluon-reload`; a plain `fw4 reload` from anywhere else would still empty
them. The daemon therefore checks once per cycle whether a set lost its
contents and drops the matching store, so the next update repopulates it.

Worst case recovery latency is one poll interval (30s), during which the rate
limit does not apply to already-known addresses. `gluon-radv-filterd` has the
same problem and handles it the same way, see below.

### Per-device ARP rate limiting

ebtables keeps a separate rate limit bucket per rule, so `gluon-arp-limiter`
could give every client device its own by adding one rule per address to
ARP_LIMIT_TLCHECK. A generated nftables ruleset cannot do that - the rules are
static and only the sets are driven by the daemon - and a plain `limit`
statement keeps a single bucket for the whole rule, which all devices would
then share.

The per-device limit is therefore a dynamic set keyed on the source address
(`add @arplimit_rate { ether saddr limit rate over 6/minute burst 50 packets }`),
which gives each address its own bucket. The node-wide 1/second limit stays a
plain `limit` statement, as it was a single ebtables rule too.

Both limits apply, as before and as the package documentation describes: a
known device passes at most 6 requests per minute, and the node as a whole at
most one per second.

The limited address is the ethernet source (ebtables' `--source`), not the ARP
sender hardware address the migration had used.

### Router advertisement filtering

`gluon-radv-filterd` drove an ebtables chain with a DROP policy: it flushed
the chain and appended a single `-s <mac> -j ACCEPT` rule for the router it
had elected, and on shutdown replaced that with a bare `-j ACCEPT`.

A chain that the daemon rewrites has no direct nftables equivalent here, as
the ruleset is generated wholesale. The rule is therefore static and the
daemon only drives two sets:

- `radv_allow` holds the address of the elected router.
- `radv_filter` enables the filtering at all. It is declared `flags interval`
  and the daemon fills it with `00:00:00:00:00:00-ff:ff:ff:ff:ff:ff`, so the
  rule matches whatever the source address is. While the set is empty - before
  the first election, and after the daemon exits - the rule cannot match and
  every advertisement passes, which is the state the bare `-j ACCEPT` used to
  produce.

Both sets are updated in a single `nft` invocation, so there is never a window
in which filtering is enabled while no address is allowed. The daemon also
notices when a firewall reload emptied the sets and programs them again, as
the ARP limiter does.

The `-c <chain>` option is gone: the set names are fixed, so there is nothing
left to configure. `respondd` reports the elected router by reading
`radv_allow` instead of listing the ebtables chain.

## Defects found and fixed

Recorded because each one made a filter silently inert, which is worth
knowing about when reviewing the rest:

- `350-mcast-dir-rules` was moved but never converted and kept its old name.
  The loader only picks up `*.lua`, so nothing ever jumped into MULTICAST_IN
  or MULTICAST_OUT and the whole multicast filter never ran.
- `355-mcast-drop.lua` matched on mark 0x4 where the original set it, killing
  the batman-adv noflood mark and letting all remaining IPv6 multicast fall
  through to the terminal drop. The all-nodes address had lost an `f`.
- IN_ONLY and OUT_ONLY dropped unconditionally where the ebtables chains only
  dropped what came in over br-client, so RAs and DHCP arriving on br-wan were
  dropped - breaking SLAAC and DHCP on the uplink.
- `ip version 6` reads the version field of the IPv4 header and can never
  match; the DHCPv6 and Babel rules never fired. In the bridge family the
  frame type is selected with `meta protocol`.
- The IPv6 OSPF rule was dropped entirely in the migration.
- `250-next-node.lua` had one rule matching bat0 as both input and output
  interface, which a forwarded frame can never do, and another repeating the
  preceding rule instead of matching the input interface.
- `ip6 nexthdr icmpv6` failed to match MLD packets with IPv6 Hop-by-Hop
  extension headers, bypassing the MLD filter; changed to `meta l4proto ipv6-icmp`.
- `meta mark set 0x4` wiped other mark bits instead of OR-ing them; changed to
  `meta mark set meta mark | 0x4`.
- `rule()` in the generator concatenated with `+` and errored on first use;
  `bridge_rule()`/`bridge_chain()` silently discarded the table argument; and
  chains were emitted in hash order, so a jump could precede its target.

## Open points

- fw4's set of valid include positions could not be verified against its
  source, which is fetched at build time rather than checked in. `chain-pre`,
  `chain-post`, `table-post` and `ruleset-pre` are used on the strength of the
  documentation only.
- Nothing here has been exercised on a real node. `nft -c` on the generated
  ruleset should be the first check on a target, followed by confirming that
  the RA, DHCP and multicast filters actually match traffic.
