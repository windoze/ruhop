-- Copyright 2024 ruhop contributors
-- Licensed under the Apache License, Version 2.0

local m, s, o
local sys = require "luci.sys"

m = Map("ruhop", translate("Ruhop VPN - Client Mode"),
    translate("Configure ruhop as a VPN client."))

-- Client Settings Section
s = m:section(TypedSection, "client", translate("Client Settings"))
s.anonymous = true
s.addremove = false

o = s:option(DynamicList, "server", translate("Server Address(es)"),
    translate("VPN server hostname(s) or IP address(es). Multiple servers for failover."))
o.datatype = "host"
o.rmempty = false

o = s:option(Value, "port_start", translate("Port Range Start"),
    translate("Starting port for port hopping range. Must match server."))
o.datatype = "port"
o.default = "4096"
o.rmempty = false

o = s:option(Value, "port_end", translate("Port Range End"),
    translate("Ending port for port hopping range. Must match server."))
o.datatype = "port"
o.default = "4196"
o.rmempty = false

o = s:option(Value, "tunnel_ip", translate("Requested Tunnel IP"),
    translate("Optional specific tunnel IP to request from server."))
o.datatype = "ip4addr"
o.rmempty = true

-- Routing Settings
s = m:section(TypedSection, "client", translate("Routing Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "route_all_traffic", translate("Route All Traffic"),
    translate("Route all traffic through the VPN tunnel."))
o.default = "1"

o = s:option(DynamicList, "excluded_routes", translate("Excluded Routes"),
    translate("CIDR routes to bypass the VPN (e.g., 192.168.1.0/24)."))
o.datatype = "cidr4"
o.rmempty = true

o = s:option(DynamicList, "dns", translate("Custom DNS Servers"),
    translate("DNS servers to use when connected. Leave empty to use server-provided DNS."))
o.datatype = "ip4addr"
o.rmempty = true

o = s:option(Flag, "mss_fix", translate("TCP MSS Clamping"),
    translate("Enable TCP MSS clamping. Recommended for gateway/router scenarios."))
o.default = "0"

-- Reconnection Settings
s = m:section(TypedSection, "client", translate("Reconnection Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "auto_reconnect", translate("Auto Reconnect"),
    translate("Automatically reconnect on connection loss."))
o.default = "1"

o = s:option(Value, "max_reconnect_attempts", translate("Max Reconnect Attempts"),
    translate("Maximum reconnection attempts. 0 for unlimited."))
o.datatype = "uinteger"
o.default = "0"
o.placeholder = "0"
o:depends("auto_reconnect", "1")

o = s:option(Value, "reconnect_delay", translate("Reconnect Delay"),
    translate("Seconds between reconnection attempts."))
o.datatype = "uinteger"
o.default = "5"
o.placeholder = "5"
o:depends("auto_reconnect", "1")

-- Hook Scripts
s = m:section(TypedSection, "client", translate("Hook Scripts"),
    translate("Scripts executed on connection state changes. Arguments: tunnel_ip netmask tun_device dns_servers"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "on_connect", translate("On Connect Script"),
    translate("Script to run on successful connection."))
o.datatype = "file"
o.rmempty = true
o.placeholder = "/etc/ruhop/on-connect.sh"

o = s:option(Value, "on_disconnect", translate("On Disconnect Script"),
    translate("Script to run on disconnection."))
o.datatype = "file"
o.rmempty = true
o.placeholder = "/etc/ruhop/on-disconnect.sh"

-- Path Loss Detection (Probe)
s = m:section(TypedSection, "probe", translate("Path Loss Detection"),
    translate("Optional probe settings for detecting and blacklisting lossy paths."))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "probe_enabled", translate("Enable Probing"),
    translate("Enable path loss detection probes."))
o.default = "0"

o = s:option(Value, "probe_interval", translate("Probe Interval"),
    translate("Seconds between probes to each address."))
o.datatype = "uinteger"
o.default = "10"
o.placeholder = "10"
o:depends("probe_enabled", "1")

o = s:option(Value, "probe_threshold", translate("Loss Threshold"),
    translate("Loss rate threshold for blacklisting (0.0-1.0)."))
o.datatype = "ufloat"
o.default = "0.5"
o.placeholder = "0.5"
o:depends("probe_enabled", "1")

o = s:option(Value, "probe_blacklist_duration", translate("Blacklist Duration"),
    translate("Seconds to keep address blacklisted."))
o.datatype = "uinteger"
o.default = "300"
o.placeholder = "300"
o:depends("probe_enabled", "1")

o = s:option(Value, "probe_min_probes", translate("Minimum Probes"),
    translate("Minimum probes before blacklist decision."))
o.datatype = "uinteger"
o.default = "3"
o.placeholder = "3"
o:depends("probe_enabled", "1")

-- Client DNS Proxy
s = m:section(TypedSection, "client_dns_proxy", translate("Client DNS Proxy"),
    translate("Optional local DNS proxy to forward queries through VPN."))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "dns_proxy_enabled", translate("Enable DNS Proxy"),
    translate("Enable local DNS proxy."))
o.default = "0"

o = s:option(Value, "dns_proxy_port", translate("DNS Proxy Port"),
    translate("Local port to listen for DNS queries."))
o.datatype = "port"
o.default = "53"
o.placeholder = "53"
o:depends("dns_proxy_enabled", "1")

o = s:option(Flag, "dns_proxy_filter_ipv6", translate("Filter IPv6"),
    translate("Filter AAAA records from DNS responses."))
o.default = "0"
o:depends("dns_proxy_enabled", "1")

o = s:option(Value, "dns_proxy_ipset", translate("IP Set Name"),
    translate("Optional Linux IP set name for resolved addresses (nftables or ipset)."))
o.datatype = "string"
o.rmempty = true
o.placeholder = "ruhop_resolved"
o:depends("dns_proxy_enabled", "1")

-- Validate port range
function m.on_commit(self)
    local uci = require "luci.model.uci".cursor()
    local port_start = tonumber(uci:get("ruhop", "@client[0]", "port_start") or 4096)
    local port_end = tonumber(uci:get("ruhop", "@client[0]", "port_end") or 4196)

    if port_start > port_end then
        uci:set("ruhop", "@client[0]", "port_start", port_end)
        uci:set("ruhop", "@client[0]", "port_end", port_start)
        uci:commit("ruhop")
    end
end

return m
