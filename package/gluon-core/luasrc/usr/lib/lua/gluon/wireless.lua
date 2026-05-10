local sysconfig = require 'gluon.sysconfig'
local site = require 'gluon.site'
local util = require 'gluon.util'

local unistd = require 'posix.unistd'

local iwinfo = require 'iwinfo'

local M = {}

function M.find_phy(config)
	return iwinfo.nl80211.phyname(config['.name'])
end

local function get_addresses(radio)
	local phy = M.find_phy(radio)
	if not phy then
		return function() end
	end

	return io.lines('/sys/class/ieee80211/' .. phy .. '/addresses')
end

local function get_wlan_mac_from_driver(radio, vif)
	local primary = sysconfig.primary_mac:lower()

	local addresses = {}
	for address in get_addresses(radio) do
		if address:lower() ~= primary then
			table.insert(addresses, address)
		end
	end

	-- Make sure we have at least 4 addresses
	if #addresses < 4 then
		return nil
	end

	return addresses[vif+1]
end

function M.supports_channel(radio, channel)
	local phy = M.find_phy(radio)
	for _, chan in ipairs(iwinfo.nl80211.freqlist(phy)) do
		if channel == chan.channel then
			return true
		end
	end
	return false
end

local radio_mac_offsets = {
	client = 0,
	mesh = 1,
	owe = 2,
	wan_radio = 3,
}

function M.get_wlan_mac(func, index, radio)
	local offset = radio_mac_offsets[func]
	if offset == nil then
		return nil
	end
	if radio then
		local addr = get_wlan_mac_from_driver(radio, offset)
		if addr then
			return addr
		end
	end

	return util.generate_mac(4*index + offset)
end

-- Iterate over all radios defined in UCI calling
-- f(radio, index, site.wifiX) for each radio found while passing
--  site.wifi24 for 2.4 GHz devices, site.wifi5 for 5 GHz ones
--  and site.wifi6 for 6 GHz devices
function M.foreach_radio(uci, f)
	local radios = {}

	uci:foreach('wireless', 'wifi-device', function(radio)
		table.insert(radios, radio)
	end)

	for index, radio in ipairs(radios) do
		local band = radio.band

		-- radio index is zero-based
		if band == '2g' then
			f(radio, index-1, site.wifi24)
		elseif band == '5g' then
			f(radio, index-1, site.wifi5)
		elseif band == '6g' then
			f(radio, index-1, site.wifi6)
		end
	end
end

function M.preserve_channels(uci)
	return uci:get_bool('gluon', 'wireless', 'preserve_channels')
end

function M.device_supports_wpa3()
	return unistd.access('/lib/gluon/features/wpa3')
end

function M.device_supports_mfp(uci)
	local supports_mfp = true

	if not M.device_supports_wpa3() then
		return false
	end

	uci:foreach('wireless', 'wifi-device', function(radio)
		local phy = M.find_phy(radio)
		local phypath = '/sys/kernel/debug/ieee80211/' .. phy .. '/'

		if not util.file_contains_line(phypath .. 'hwflags', 'MFP_CAPABLE') then
			supports_mfp = false
			return false
		end
	end)

	return supports_mfp
end

function M.device_uses_wlan(uci)
	local ret = false

	uci:foreach('wireless', 'wifi-device', function()
		ret = true
		return false
	end)

	return ret
end

function M.device_uses_band(uci, band)
	local ret = false

	uci:foreach('wireless', 'wifi-device', function(radio)
		if radio.band == band then
			ret = true
			return false
		end
	end)

	return ret
end

local PRIMARY_CHANNELS_5G = {
	36, 40, 44, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128,
	132, 136, 140, 144,
	149, 153, 157, 161, 165, 169, 173, 177,
}

-- Primary -> sibling channels of the HT block at the given width.
-- Blocks respect the UNII-1+2, UNII-2-extended and UNII-3 sub-band boundaries.
local HT_BLOCKS_5G = {
	[40] = {
		{36, 40},   {44, 48},   {52, 56},   {60, 64},
		{100, 104}, {108, 112}, {116, 120}, {124, 128},
		{132, 136}, {140, 144},
		{149, 153}, {157, 161},
	},
	[80] = {
		{36, 40, 44, 48},     {52, 56, 60, 64},
		{100, 104, 108, 112}, {116, 120, 124, 128}, {132, 136, 140, 144},
		{149, 153, 157, 161},
	},
	[160] = {
		{36, 40, 44, 48, 52, 56, 60, 64},
		{100, 104, 108, 112, 116, 120, 124, 128},
		{149, 153, 157, 161, 165, 169, 173, 177},
	},
}

local function parse_chanlist(s)
	local set = {}
	for group in s:gmatch('%S+') do
		local single = group:match('^(%d+)$')
		if single then
			set[tonumber(single)] = true
		else
			local from, to = group:match('^(%d+)-(%d+)$')
			if from and to then
				from, to = tonumber(from), tonumber(to)
				for _, ch in ipairs(PRIMARY_CHANNELS_5G) do
					if ch >= from and ch <= to then
						set[ch] = true
					end
				end
			end
		end
	end
	return set
end

-- Translate a 5 GHz outdoor_chanlist into the set of primary channels whose
-- full HT block (at the given channel_width) is fully contained in the
-- user-allowed range. Returns:
--   * nil if chanlist is nil
--   * chanlist unchanged for 20 MHz or unknown widths (caller passes through)
--   * a sorted, space-separated list of primary channels for 40/80/160 MHz
--   * nil if the filter is non-trivial but yields no compatible primaries
function M.expand_chanlist(chanlist, channel_width)
	if not chanlist then
		return nil
	end
	local blocks = HT_BLOCKS_5G[channel_width]
	if not blocks then
		return chanlist
	end

	local allowed = parse_chanlist(chanlist)
	local picked = {}
	local result = {}
	for _, block in ipairs(blocks) do
		local all_in = true
		for _, ch in ipairs(block) do
			if not allowed[ch] then
				all_in = false
				break
			end
		end
		if all_in then
			for _, ch in ipairs(block) do
				if not picked[ch] then
					picked[ch] = true
					result[#result+1] = ch
				end
			end
		end
	end

	if #result == 0 then
		return nil
	end

	table.sort(result)
	return table.concat(result, ' ')
end

return M
