-- Copyright 2024 ruhop contributors
-- Licensed under the Apache License, Version 2.0

local m, s, o
local sys = require "luci.sys"

m = Map("ruhop", translate("Ruhop VPN - Server Mode"),
    translate("Configure ruhop as a VPN server."))

-- Server Settings Section
s = m:section(TypedSection, "server", translate("Server Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "listen", translate("Listen Address"),
    translate("IP address to bind to. Use 0.0.0.0 for all interfaces."))
o.datatype = "ipaddr"
o.default = "0.0.0.0"
o.rmempty = false

o = s:option(Value, "port_start", translate("Port Range Start"),
    translate("Starting port for port hopping range."))
o.datatype = "port"
o.default = "4096"
o.rmempty = false

o = s:option(Value, "port_end", translate("Port Range End"),
    translate("Ending port for port hopping range."))
o.datatype = "port"
o.default = "4196"
o.rmempty = false

o = s:option(Value, "tunnel_network", translate("Tunnel Network"),
    translate("CIDR notation network for client IP allocation (e.g., 10.0.0.0/24)."))
o.datatype = "cidr4"
o.default = "10.0.0.0/24"
o.rmempty = false

o = s:option(Value, "tunnel_ip", translate("Server Tunnel IP"),
    translate("Optional server's tunnel IP. Defaults to network_address + 1 if not set."))
o.datatype = "ip4addr"
o.placeholder = "10.0.0.1"
o.rmempty = true

o = s:option(Value, "max_clients", translate("Maximum Clients"),
    translate("Maximum number of concurrent client connections."))
o.datatype = "uinteger"
o.default = "100"
o.placeholder = "100"

-- NAT Settings
s = m:section(TypedSection, "server", translate("NAT Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable_nat", translate("Enable NAT"),
    translate("Enable NAT/masquerading for client traffic."))
o.default = "1"

o = s:option(Value, "nat_interface", translate("NAT Interface"),
    translate("Outbound interface for NAT. Auto-detected if not set."))
o.datatype = "string"
o.placeholder = "eth0"
o.rmempty = true
o:depends("enable_nat", "1")

-- DNS Proxy Settings
s = m:section(TypedSection, "server", translate("DNS Proxy Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "dns_proxy", translate("Enable DNS Proxy"),
    translate("Enable DNS proxy on tunnel IP for clients."))
o.default = "0"

o = s:option(DynamicList, "dns_servers", translate("Upstream DNS Servers"),
    translate("DNS servers to forward queries to. Formats: IP, IP:port, IP/udp, IP/tcp, https://..., tls://..."))
o.datatype = "string"
o.placeholder = "8.8.8.8"
o:depends("dns_proxy", "1")

-- Validate port range
function m.on_commit(self)
    local uci = require "luci.model.uci".cursor()
    local port_start = tonumber(uci:get("ruhop", "@server[0]", "port_start") or 4096)
    local port_end = tonumber(uci:get("ruhop", "@server[0]", "port_end") or 4196)

    if port_start > port_end then
        -- Swap if needed
        uci:set("ruhop", "@server[0]", "port_start", port_end)
        uci:set("ruhop", "@server[0]", "port_end", port_start)
        uci:commit("ruhop")
    end
end

return m
