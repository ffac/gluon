-- radv_allow holds the address of the router elected by gluon-radv-filterd.
--
-- radv_filter enables the filtering at all: the daemon fills it with an
-- interval covering every address once it has elected a router, so that the
-- rule below matches whatever the source address is. While the set is empty -
-- before the first election, and after the daemon exits - the rule cannot
-- match and all router advertisements pass.
bridge_table('pre', [[set radv_allow {
	type ether_addr
}

set radv_filter {
	type ether_addr
	flags interval
}
]])

bridge_rule('FORWARD', 'ether saddr @radv_filter iifname "bat0" icmpv6 type nd-router-advert ether saddr != @radv_allow drop')
