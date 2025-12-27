-- Copyright 2024 ruhop contributors
-- Licensed under the Apache License, Version 2.0

module("luci.controller.ruhop", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/ruhop") then
        return
    end

    local page

    page = entry({"admin", "vpn", "ruhop"}, firstchild(), _("Ruhop VPN"), 90)
    page.dependent = false
    page.acl_depends = { "luci-app-ruhop" }

    page = entry({"admin", "vpn", "ruhop", "general"}, cbi("ruhop/general"), _("General Settings"), 10)
    page.leaf = true
    page.acl_depends = { "luci-app-ruhop" }

    page = entry({"admin", "vpn", "ruhop", "server"}, cbi("ruhop/server"), _("Server Mode"), 20)
    page.leaf = true
    page.acl_depends = { "luci-app-ruhop" }

    page = entry({"admin", "vpn", "ruhop", "client"}, cbi("ruhop/client"), _("Client Mode"), 30)
    page.leaf = true
    page.acl_depends = { "luci-app-ruhop" }

    page = entry({"admin", "vpn", "ruhop", "status"}, template("ruhop/status"), _("Status"), 40)
    page.leaf = true
    page.acl_depends = { "luci-app-ruhop" }

    page = entry({"admin", "vpn", "ruhop", "log"}, template("ruhop/log"), _("Log"), 50)
    page.leaf = true
    page.acl_depends = { "luci-app-ruhop" }

    -- API endpoints
    entry({"admin", "vpn", "ruhop", "status_data"}, call("action_status")).leaf = true
    entry({"admin", "vpn", "ruhop", "log_data"}, call("action_log")).leaf = true
    entry({"admin", "vpn", "ruhop", "start"}, call("action_start")).leaf = true
    entry({"admin", "vpn", "ruhop", "stop"}, call("action_stop")).leaf = true
    entry({"admin", "vpn", "ruhop", "restart"}, call("action_restart")).leaf = true
end

function action_status()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local json = require "luci.jsonc"

    local status = {
        running = false,
        role = "",
        state = "",
        uptime = "",
        tunnel_ip = "",
        peer_ip = "",
        tun_device = "",
        rx_bytes = 0,
        tx_bytes = 0,
        rx_packets = 0,
        tx_packets = 0,
        sessions = 0,
        blacklist = {}
    }

    -- Check if ruhop is running
    local pid = sys.exec("pgrep -x ruhop 2>/dev/null"):match("^%d+")
    if pid then
        status.running = true

        -- Get detailed status from ruhop
        local output = sys.exec("/usr/bin/ruhop status --json 2>/dev/null")
        if output and output ~= "" then
            local parsed = json.parse(output)
            if parsed then
                status.role = parsed.role or ""
                status.state = parsed.state or ""
                status.uptime = parsed.uptime or ""
                status.tunnel_ip = parsed.tunnel_ip or ""
                status.peer_ip = parsed.peer_ip or ""
                status.tun_device = parsed.tun_device or ""
                status.rx_bytes = parsed.rx_bytes or 0
                status.tx_bytes = parsed.tx_bytes or 0
                status.rx_packets = parsed.rx_packets or 0
                status.tx_packets = parsed.tx_packets or 0
                status.sessions = parsed.sessions or 0
                status.blacklist = parsed.blacklist or {}
            end
        end
    end

    http.prepare_content("application/json")
    http.write_json(status)
end

function action_log()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local lines = http.formvalue("lines") or 50

    local log = sys.exec("logread -e ruhop 2>/dev/null | tail -n " .. tonumber(lines))
    if not log or log == "" then
        log = sys.exec("journalctl -u ruhop -n " .. tonumber(lines) .. " --no-pager 2>/dev/null")
    end

    http.prepare_content("text/plain")
    http.write(log or "No log entries found")
end

function action_start()
    local sys = require "luci.sys"
    local http = require "luci.http"

    sys.call("/etc/init.d/ruhop start >/dev/null 2>&1")

    http.prepare_content("application/json")
    http.write_json({ success = true })
end

function action_stop()
    local sys = require "luci.sys"
    local http = require "luci.http"

    sys.call("/etc/init.d/ruhop stop >/dev/null 2>&1")

    http.prepare_content("application/json")
    http.write_json({ success = true })
end

function action_restart()
    local sys = require "luci.sys"
    local http = require "luci.http"

    sys.call("/etc/init.d/ruhop restart >/dev/null 2>&1")

    http.prepare_content("application/json")
    http.write_json({ success = true })
end
