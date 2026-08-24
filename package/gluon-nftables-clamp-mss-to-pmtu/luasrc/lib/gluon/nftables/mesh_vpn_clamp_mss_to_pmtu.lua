include('mesh_vpn_clamp_mss_to_pmtu', {
	position = 'chain-pre',
	chain = 'mangle_forward',
})
