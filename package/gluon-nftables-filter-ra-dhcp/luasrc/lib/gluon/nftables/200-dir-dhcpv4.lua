local uci = require('simple-uci').cursor()

local gw_mode = uci:get('network', 'gluon_bat0', 'gw_mode')

if gw_mode ~= 'server' then
	bridge_rule('FORWARD', 'meta protocol ip udp dport 67 jump out_only')
	bridge_rule('OUTPUT', 'meta protocol ip udp dport 67 jump out_only')

	bridge_rule('FORWARD', 'meta protocol ip udp dport 68 jump in_only')
	bridge_rule('INPUT', 'meta protocol ip udp dport 68 jump in_only')
end
