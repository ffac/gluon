-- ebtables' '-d Multicast' matches any destination MAC with the group bit
-- set, which includes broadcast frames
local multicast = 'ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00'

bridge_rule('PREROUTING', multicast .. ' ibrname "br-client" iifname "bat0" jump multicast_in', 'nat')
bridge_rule('OUTPUT', multicast .. ' obrname "br-client" oifname "bat0" jump multicast_out')
bridge_rule('FORWARD', multicast .. ' obrname "br-client" oifname "bat0" jump multicast_out')

bridge_rule('MULTICAST_IN', 'meta l4proto ipv6-icmp jump multicast_in_icmpv6', 'nat')
bridge_rule('MULTICAST_OUT', 'meta l4proto ipv6-icmp jump multicast_out_icmpv6')
