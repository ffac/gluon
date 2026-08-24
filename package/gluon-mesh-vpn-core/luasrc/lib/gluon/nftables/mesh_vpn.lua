-- The rule matches on the group of the sending socket and on the outgoing
-- interface, neither of which is known in fw4's dstnat (prerouting) chain, so
-- the include ships an output hooked nat chain of its own.
include('mesh_vpn_dns', {
	position = 'table-post',
})
