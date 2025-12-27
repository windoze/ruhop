-- Copyright 2024 ruhop contributors
-- Licensed under the Apache License, Version 2.0

local m, s, o
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

m = Map("ruhop", translate("Ruhop VPN - General Settings"),
    translate("Ruhop is a UDP-based VPN with port hopping capabilities for traffic obfuscation."))

-- Service Control Section
s = m:section(TypedSection, "ruhop", translate("Service Control"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"))
o.rmempty = false

o = s:option(ListValue, "mode", translate("Mode"))
o:value("client", translate("Client"))
o:value("server", translate("Server"))
o.default = "client"

o = s:option(Value, "config", translate("Config File Path"))
o.default = "/etc/ruhop/ruhop.toml"
o.datatype = "string"
o.rmempty = false

-- Common Settings Section
s = m:section(TypedSection, "common", translate("Common Settings"),
    translate("Settings shared between server and client modes."))
s.anonymous = true
s.addremove = false

o = s:option(Value, "key", translate("Pre-shared Key"),
    translate("Encryption key that must match between client and server."))
o.password = true
o.datatype = "string"
o.rmempty = false

o = s:option(Value, "mtu", translate("MTU"),
    translate("Maximum Transmission Unit for the tunnel interface. Minimum: 576"))
o.datatype = "range(576,9000)"
o.default = "1400"
o.placeholder = "1400"

o = s:option(ListValue, "log_level", translate("Log Level"))
o:value("error", translate("Error"))
o:value("warn", translate("Warning"))
o:value("info", translate("Info"))
o:value("debug", translate("Debug"))
o:value("trace", translate("Trace"))
o.default = "info"

o = s:option(Value, "log_file", translate("Log File Directory"),
    translate("Optional directory path for file-based logging."))
o.datatype = "directory"
o.rmempty = true
o.placeholder = "/var/log/ruhop"

o = s:option(ListValue, "log_rotation", translate("Log Rotation"))
o:value("hourly", translate("Hourly"))
o:value("daily", translate("Daily"))
o:value("never", translate("Never"))
o.default = "daily"
o:depends("log_file", true)

o = s:option(Flag, "obfuscation", translate("Packet Obfuscation"),
    translate("Enable packet obfuscation with random noise bytes."))
o.default = "0"

o = s:option(Value, "heartbeat_interval", translate("Heartbeat Interval"),
    translate("Seconds between keep-alive packets."))
o.datatype = "uinteger"
o.default = "30"
o.placeholder = "30"

o = s:option(Value, "tun_device", translate("TUN Device Name"),
    translate("Optional custom TUN device name. Defaults to 'ruhop'."))
o.datatype = "string"
o.placeholder = "ruhop"
o.rmempty = true

o = s:option(ListValue, "use_nftables", translate("Firewall Backend"),
    translate("Select firewall backend. OpenWRT with fw4 uses nftables."))
o:value("", translate("Auto-detect"))
o:value("1", translate("nftables (fw4)"))
o:value("0", translate("iptables (fw3)"))
o.default = "1"

return m
