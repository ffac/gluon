#!/usr/bin/lua

local RESOLV_CONF = '/var/gluon/wan-dnsmasq/resolv.conf'


local stat = require 'posix.sys.stat'
local unistd = require 'posix.unistd'
local ubus = require('ubus').connect()
local uci = require('simple-uci').cursor()
local util = require 'gluon.util'


if not ubus then
	os.execute("logger -t gluon-wan-dnsmasq 'failed to connect to ubus, keeping resolv.conf'")
	os.exit(1)
end

local new_servers = ''
local read_failed = false

local function append_server(server)
	new_servers = new_servers .. 'nameserver ' .. server .. '\n'
end


local function handled_interfaces()
	local interfaces = {}

	for _, path in ipairs(util.glob('/lib/gluon/wan-dnsmasq/interface.d/*')) do
		for interface in io.lines(path) do
			table.insert(interfaces, interface)
		end
	end

	return interfaces
end


local function handle_interface(status)
	local ifname = status.device
	local servers = status.inactive['dns-server']

	for _, server in ipairs(servers) do
		if server:match('^fe80:') then
			append_server(server .. '%' .. ifname)
		else
			append_server(server)
		end
	end
end

local function append_interface_servers(iface)
	local status, err = ubus:call('network.interface.' .. iface, 'status', {})

	if not status then
		-- 4 is UBUS_STATUS_NOT_FOUND: the interface doesn't exist, so
		-- there are no servers to add. Any other error (typically a
		-- timeout while netifd is busy) means that we don't know the
		-- servers of this interface.
		if err ~= 4 then
			read_failed = true
		end
		return
	end

	handle_interface(status)
end


local static = uci:get_first('gluon-wan-dnsmasq', 'static', 'server')

if type(static) == 'table' and #static > 0 then
	for _, server in ipairs(static) do
		append_server(server)
	end
else
	for _, interface in ipairs(handled_interfaces()) do
		pcall(append_interface_servers, interface)
	end
end


if read_failed then
	-- A stale invocation (e.g. from the start of a network restart)
	-- must not replace the result of a newer one with incomplete data.
	-- Every uplink interface event runs this script again, so the file
	-- is updated as soon as the interfaces can be read again.
	os.execute("logger -t gluon-wan-dnsmasq 'failed to read the status of an uplink interface, keeping resolv.conf'")
	os.exit(1)
end

local old_servers = util.readfile(RESOLV_CONF)

if new_servers ~= old_servers then
	stat.mkdir('/var/gluon')
	stat.mkdir('/var/gluon/wan-dnsmasq')

	-- Invocations can overlap, so don't share the temporary file
	local tmp = RESOLV_CONF .. '.tmp.' .. unistd.getpid()

	local f = io.open(tmp, 'w')
	f:write(new_servers)
	f:close()

	os.rename(tmp, RESOLV_CONF)
end
