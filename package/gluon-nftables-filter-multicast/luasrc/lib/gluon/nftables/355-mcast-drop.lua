bridge_rule('MULTICAST_OUT', 'ip6 daddr ff02::1/128 drop')
bridge_rule('MULTICAST_OUT', 'ip6 daddr ff02::15c/128 drop') -- Gluon VXLAN multicast group
bridge_rule('MULTICAST_OUT', 'ip6 daddr ff00::/8 meta mark set meta mark | 0x4 return') -- batman-adv "noflood" mark
bridge_rule('MULTICAST_OUT', 'drop')
