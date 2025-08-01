local bit = require 'bit32'
local posix_fcntl = require 'posix.fcntl'
local posix_glob = require 'posix.glob'
local posix_syslog = require 'posix.syslog'
local posix_unistd = require 'posix.unistd'
local hash = require 'hash'
local sysconfig = require 'gluon.sysconfig'
local site = require 'gluon.site'
local unistd = require 'posix.unistd'


local M = {}

-- Writes all lines from the file input to the file output except those starting with prefix
-- Doesn't close the output file, but returns the file object
local function do_filter_prefix(input, output, prefix)
	local f = io.open(output, 'w+')
	local l = prefix:len()

	for line in io.lines(input) do
		if line:sub(1, l) ~= prefix then
			f:write(line, '\n')
		end
	end

	return f
end

function M.trim(str)
	return (str:gsub("^%s*(.-)%s*$", "%1"))
end

function M.contains(table, value)
	for k, v in pairs(table) do
		if value == v then
			return k
		end
	end
	return false
end

function M.file_contains_line(path, value)
	if not unistd.access(path) then
		return false
	end

	for line in io.lines(path) do
		if line == value then
			return true
		end
	end
	return false
end

function M.add_to_set(t, itm)
	for _,v in ipairs(t) do
		if v == itm then return false end
	end
	table.insert(t, itm)
	return true
end

function M.remove_from_set(t, itm)
	local i = 1
	local changed = false
	while i <= #t do
		if t[i] == itm then
			table.remove(t, i)
			changed = true
		else
			i = i + 1
		end
	end
	return changed
end

-- Removes all lines starting with a prefix from a file, optionally adding a new one
function M.replace_prefix(file, prefix, add)
	local tmp = file .. '.tmp'
	local f = do_filter_prefix(file, tmp, prefix)
	if add then
		f:write(add)
	end
	f:close()
	os.rename(tmp, file)
end

local function readall(f)
	if not f then
		return nil
	end

	local data = f:read('*a')
	f:close()
	return data
end

function M.readfile(file)
	return readall(io.open(file))
end

function M.exec(command)
	return readall(io.popen(command))
end

function M.node_id()
	return (string.gsub(sysconfig.primary_mac, ':', ''))
end

function M.default_hostname()
	return site.hostname_prefix('') .. M.node_id()
end

function M.domain_seed_bytes(key, length)
	local ret = ''
	local v = ''
	local i = 0

	-- Inspired by HKDF key expansion, but much simpler, as we don't need
	-- cryptographic strength
	while ret:len() < 2*length do
		i = i + 1
		v = hash.md5(v .. key .. site.domain_seed():lower() .. i)
		ret = ret .. v
	end

	return ret:sub(0, 2*length)
end

function M.get_mesh_devices(uconn)
	local dump = uconn:call("network.interface", "dump", {})
	local devices = {}
	for _, interface in ipairs(dump.interface) do
		if ( (interface.proto == "gluon_mesh") and interface.up ) then
			table.insert(devices, interface.device)
		end
	end
	return devices
end

-- Returns a table of all interfaces with a given role
--
-- If exclusive is set to true, only interfaces that have no other role
-- are returned; this is used to ensure that the client role is not active
-- at the same time as any other role
--
-- A list of additional options to collect from the UCI interface
-- sections can be passed. The return value is a table mapping interface names
-- to tables of the extra options and their respective values.
function M.get_role_interfaces_with_options(uci, role, extra_keys, exclusive)
	local ret = {}

	local function add(name, extra_values)
		-- Interface names with a / prefix refer to sysconfig interfaces
		-- (lan_ifname/wan_ifname/single_ifname)
		if string.sub(name, 1, 1) == '/' then
			name = sysconfig[string.sub(name, 2) .. '_ifname'] or ''
		end
		for iface in string.gmatch(name, '%S+') do
			ret[iface] = extra_values
		end
	end

	uci:foreach('gluon', 'interface', function(s)
		local roles = s.role or {}
		local extra_values = {}
		for _, key in ipairs(extra_keys) do
			extra_values[key] = s[key]
		end
		if M.contains(roles, role) and (not exclusive or #roles == 1) then
			add(s.name, extra_values)
		end
	end)

	return ret
end

-- Returns a list of all interfaces with a given role
--
-- If exclusive is set to true, only interfaces that have no other role
-- are returned; this is used to ensure that the client role is not active
-- at the same time as any other role
function M.get_role_interfaces(uci, role, exclusive)
	local ifaces = M.get_role_interfaces_with_options(uci, role, {}, exclusive)

	local ret = {}
	for iface in pairs(ifaces) do
		table.insert(ret, iface)
	end
	table.sort(ret)

	return ret
end

-- Safe glob: returns an empty table when the glob fails because of
-- a non-existing path
function M.glob(pattern)
	return posix_glob.glob(pattern, 0) or {}
end

-- Generates a (hopefully) unique MAC address
-- The parameter defines the ID to add to the MAC address

local if_mac_offsets = {
	wan = 0,
	primary = 3,
	mesh_other = 4,
	mesh_vpn = 7,
}

function M.generate_mac(index)

	local hashed = string.sub(hash.md5(sysconfig.primary_mac), 0, 12)
	local m1, m2, m3, m4, m5, m6 = string.match(hashed, '(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)')

	m1 = tonumber(m1, 16)
	m6 = tonumber(m6, 16)

	m1 = bit.bor(m1, 0x02)  -- set locally administered bit
	m1 = bit.band(m1, 0xFE) -- unset the multicast bit

	-- It's necessary that the first 45 bits of the MAC address don't
	-- vary on a single hardware interface, since some chips are using
	-- a hardware MAC filter. (e.g 'rt305x')

	m6 = bit.band(m6, 0xF8) -- zero the last three bits (space needed for counting)
	m6 = bit.band(m6 + index, 0xFF) -- add virtual interface id (check overflow)

	return string.format('%02x:%s:%s:%s:%s:%02x', m1, m2, m3, m4, m5, m6)
end

function M.generate_mac_by_name(func)
	-- when radio is set, use radio_mac_offsets, else use if_mac_offsets for the interfaces
	local idx

	idx = if_mac_offsets[func]
	if idx == nil then
		return nil
	end

	return M.generate_mac(idx)
end

function M.get_uptime()
	local uptime_file = M.readfile("/proc/uptime")
	if uptime_file == nil then
		-- Something went wrong reading "/proc/uptime"
		return nil
	end
	return tonumber(uptime_file:match('^[^ ]+'))
end

function M.log(message, verbose)
	if verbose then
		io.stdout:write(message .. '\n')
	end

	posix_syslog.syslog(posix_syslog.LOG_INFO, message)
end

local function close_fds(fds)
	for _, fd in pairs(fds) do
		posix_unistd.close(fd)
	end
end

M.subprocess = {}

M.subprocess.DEVNULL = -1
M.subprocess.PIPE = 1

-- Execute a program found using command PATH search, like the shell.
-- Return the pid, as well as the I/O streams as pipes or nil on error.
function M.subprocess.popen(path, argt, options)
	argt = argt or {}
	local childfds = {}
	local parentfds = {}
	local stdiostreams = {stdin = 0, stdout = 1, stderr = 2}

	for iostream in pairs(stdiostreams) do
		if options[iostream] == M.subprocess.PIPE then
			local piper, pipew = posix_unistd.pipe()
			if iostream == "stdin" then
				childfds[iostream] = piper
				parentfds[iostream] = pipew
			else
				childfds[iostream] = pipew
				parentfds[iostream] = piper
			end
		end
	end

	-- childfds: r0, w1, w2
	-- parentfds: w0, r1, r2

	local pid, errmsg, errnum = posix_unistd.fork()

	if pid == nil then
		close_fds(parentfds)
		close_fds(childfds)
		return nil, errmsg, errnum
	elseif pid == 0 then
		local null = -1
		if M.contains(options, M.subprocess.DEVNULL) then
			-- only open if there's anything to discard
			null = posix_fcntl.open('/dev/null', posix_fcntl.O_RDWR)
		end

		for iostream, fd in pairs(stdiostreams) do
			local option = options[iostream]
			if option == M.subprocess.DEVNULL then
				posix_unistd.dup2(null, fd)
			elseif option == M.subprocess.PIPE then
				posix_unistd.dup2(childfds[iostream], fd)
			end
		end
		close_fds(childfds)
		close_fds(parentfds)

		-- close potential null
		if null > 2 then
			posix_unistd.close(null)
		end

		posix_unistd.execp(path, argt)
		posix_unistd._exit(127)
	end

	close_fds(childfds)

	return pid, parentfds
end

function M.get_mem_total()
	for line in io.lines('/proc/meminfo') do
		local match = line:match('^MemTotal:%s+(%d+)')
		if match then
			return tonumber(match)
		end
	end
end

return M
