-- Bridge loop avoidance
-- nftables cannot compare two packet fields, so the ebtables --arp-gratuitous
-- condition is dropped; the batman-adv claim destination MAC is specific enough.
bridge_rule('MULTICAST_OUT', 'arp operation reply arp daddr ether & ff:ff:ff:fc:00:00 == ff:43:05:00:00:00 return')
bridge_rule('MULTICAST_OUT', 'arp operation reply arp daddr ether & ff:ff:ff:ff:00:00 == ff:43:05:05:00:00 return')

bridge_rule('MULTICAST_OUT', 'arp operation reply arp saddr ip 0.0.0.0 drop')
bridge_rule('MULTICAST_OUT', 'arp operation request arp daddr ip 0.0.0.0 drop')
bridge_rule('MULTICAST_OUT', 'ether type arp return')
