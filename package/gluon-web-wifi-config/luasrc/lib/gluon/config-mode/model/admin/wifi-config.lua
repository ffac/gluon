local iwinfo = require 'iwinfo'
local uci = require("simple-uci").cursor()
local site = require 'gluon.site'
local wireless = require 'gluon.wireless'
local util = require 'gluon.util'

local function txpower_list(phy)
	local list = iwinfo.nl80211.txpwrlist(phy) or { }
	local off  = tonumber(iwinfo.nl80211.txpower_offset(phy)) or 0
	local new  = { }
	local prev = -1
	for _, val in ipairs(list) do
		local dbm = val.dbm + off
		local mw  = math.floor(10 ^ (dbm / 10))
		if mw ~= prev then
			prev = mw
			table.insert(new, {
				display_dbm = dbm,
				display_mw  = mw,
				driver_dbm  = val.dbm,
			})
		end
	end
	return new
end

local f = Form(translate("WLAN"))

f:section(Section, nil, translate(
	"You can enable or disable your node's client and mesh network "
	.. "SSIDs here. Please don't disable the mesh network without "
	.. "a good reason, so other nodes can mesh with yours.<br><br>"
	.. "It is also possible to configure the WLAN adapters transmission power "
	.. "here. Please note that the transmission power values include the antenna gain "
	.. "where available, but there are many devices for which the gain is unavailable or inaccurate."
))


local mesh_vifs_5ghz = {}

local function add_or_remove_role(roles, role, disabled)
	if disabled == true then
		util.remove_from_set(roles, role)
	elseif disabled == false then
		util.add_to_set(roles, role)
	end
end

local function vif_option(section, role_name, band, msg)
	local config_roles = uci:get('gluon', band, 'role') or {}
	local o = section:option(Flag, band .. '_' .. role_name .. '_enabled', msg)
	o.default = util.contains(config_roles, role_name)

	function o:write(data)
		-- this does race for multiple options without additional read before write in o:write
		local roles = uci:get('gluon', band, 'role') or {}
		add_or_remove_role(roles, role_name, not data)
		uci:set('gluon', band, 'role', roles)
	end

	return o
end

local bands = {}

uci:foreach('wireless', 'wifi-device', function(config)
	local radio = config['.name']

	local is_5ghz = false
	local title
	local band = config.band

	local p
	-- store section to add txpower and htmode to
	if bands and bands[band] then
		p = bands[band]
	else
		if band == '2g' then
			title = translate("2.4GHz WLAN")
		elseif band == '6g' then
			title = translate("6GHz WLAN")
		elseif band == '5g' then
			is_5ghz = true
			title = translate("5GHz WLAN")
		else
			return
		end

		p = f:section(Section, title)

		vif_option(p, 'client', band, translate('Enable client network (access point)'))

		local mesh_vif = vif_option(p, 'mesh', band, translate("Enable mesh network (802.11s)"))
		if is_5ghz then
			table.insert(mesh_vifs_5ghz, mesh_vif)
		end
		bands[band] = p
	end

	-- txpowerlist
	local phy = wireless.find_phy(config)
	if not phy then
		return
	end

	local txpowers = txpower_list(phy)
	if #txpowers <= 1 then
		return
	end

	local tp = p:option(ListValue, 'txpower_' .. radio, translate("Transmission power").. ' (' .. radio .. ')')
	tp.default = uci:get('gluon', 'wireless', 'txpower_' .. radio) or 'default'

	tp:value('default', translate("(default)"))

	table.sort(txpowers, function(a, b) return a.driver_dbm > b.driver_dbm end)

	for _, entry in ipairs(txpowers) do
		tp:value(entry.driver_dbm, string.format("%i dBm (%i mW)", entry.display_dbm, entry.display_mw))
	end

	function tp:write(data)
		if data == 'default' then
			data = nil
		end
		uci:set('gluon', 'wireless', 'txpower_' .. radio, data)
	end

	-- htmode
	local ht = p:option(ListValue, 'htmode_' .. radio, translate('HT Mode') .. ' (' .. radio .. ')')
	ht.default = uci:get('gluon', 'wireless', 'htmode_' .. radio) or 'default'
	ht:value('default', translate("(default)"))

	for mode, available in pairs(iwinfo.nl80211.htmodelist(phy)) do
		if available then
			ht:value(mode, mode)
		end
	end

	function ht:write(data)
		if data == 'default' then
			data = nil
		end
		uci:set('gluon', 'wireless', 'htmode_' .. radio, data)
	end
end)


if wireless.device_uses_band(uci, '5g') and not wireless.preserve_channels(uci) then
	local r = f:section(Section, translate("Outdoor Installation"), translate(
		"Configuring the node for outdoor use tunes the 5 GHz radio to a frequency "
		.. "and transmission power that conforms with the local regulatory requirements. "
		.. "It also enables dynamic frequency selection (DFS; radar detection). At the "
		.. "same time, mesh functionality is disabled as it requires neighbouring nodes "
		.. "to stay on the same channel permanently."
	))

	local outdoor = r:option(Flag, 'outdoor', translate("Node will be installed outdoors"))
	outdoor.default = uci:get_bool('gluon', 'wireless', 'outdoor')

	for _, mesh_vif in ipairs(mesh_vifs_5ghz) do
		mesh_vif:depends(outdoor, false)
		if outdoor.default then
			mesh_vif.default = not site.wifi5.mesh.disabled(false)
		end
	end

	function outdoor:write(data)
		uci:set('gluon', 'wireless', 'outdoor', data)
	end
end


function f:write()
	uci:commit('gluon')
	os.execute('/usr/bin/gluon-reconfigure')
	uci:commit('network')
	uci:commit('wireless')
end

return f
