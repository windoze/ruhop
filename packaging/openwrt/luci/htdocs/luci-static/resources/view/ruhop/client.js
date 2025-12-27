'use strict';
'require view';
'require form';
'require uci';

return view.extend({
    load: function() {
        return uci.load('ruhop');
    },

    render: function() {
        var m, s, o;

        m = new form.Map('ruhop', _('Ruhop VPN - Client Mode'),
            _('Configure ruhop as a VPN client.'));

        // Client Settings Section
        s = m.section(form.TypedSection, 'client', _('Client Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.DynamicList, 'server', _('Server Address(es)'),
            _('VPN server hostname(s) or IP address(es). Multiple servers for failover.'));
        o.datatype = 'host';
        o.rmempty = false;

        o = s.option(form.Value, 'port_start', _('Port Range Start'),
            _('Starting port for port hopping range. Must match server.'));
        o.datatype = 'port';
        o.default = '4096';
        o.rmempty = false;

        o = s.option(form.Value, 'port_end', _('Port Range End'),
            _('Ending port for port hopping range. Must match server.'));
        o.datatype = 'port';
        o.default = '4196';
        o.rmempty = false;

        o = s.option(form.Value, 'tunnel_ip', _('Requested Tunnel IP'),
            _('Optional specific tunnel IP to request from server.'));
        o.datatype = 'ip4addr';
        o.rmempty = true;

        // Routing Settings
        s = m.section(form.TypedSection, 'client', _('Routing Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'route_all_traffic', _('Route All Traffic'),
            _('Route all traffic through the VPN tunnel.'));
        o.default = '1';

        o = s.option(form.DynamicList, 'excluded_routes', _('Excluded Routes'),
            _('CIDR routes to bypass the VPN (e.g., 192.168.1.0/24).'));
        o.datatype = 'cidr4';
        o.rmempty = true;

        o = s.option(form.DynamicList, 'dns', _('Custom DNS Servers'),
            _('DNS servers to use when connected. Leave empty to use server-provided DNS.'));
        o.datatype = 'ip4addr';
        o.rmempty = true;

        o = s.option(form.Flag, 'mss_fix', _('TCP MSS Clamping'),
            _('Enable TCP MSS clamping. Recommended for gateway/router scenarios.'));
        o.default = '0';

        // Reconnection Settings
        s = m.section(form.TypedSection, 'client', _('Reconnection Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'auto_reconnect', _('Auto Reconnect'),
            _('Automatically reconnect on connection loss.'));
        o.default = '1';

        o = s.option(form.Value, 'max_reconnect_attempts', _('Max Reconnect Attempts'),
            _('Maximum reconnection attempts. 0 for unlimited.'));
        o.datatype = 'uinteger';
        o.default = '0';
        o.placeholder = '0';
        o.depends('auto_reconnect', '1');

        o = s.option(form.Value, 'reconnect_delay', _('Reconnect Delay'),
            _('Seconds between reconnection attempts.'));
        o.datatype = 'uinteger';
        o.default = '5';
        o.placeholder = '5';
        o.depends('auto_reconnect', '1');

        // Hook Scripts
        s = m.section(form.TypedSection, 'client', _('Hook Scripts'),
            _('Scripts executed on connection state changes. Arguments: tunnel_ip netmask tun_device dns_servers'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Value, 'on_connect', _('On Connect Script'),
            _('Script to run on successful connection.'));
        o.datatype = 'file';
        o.rmempty = true;
        o.placeholder = '/etc/ruhop/on-connect.sh';

        o = s.option(form.Value, 'on_disconnect', _('On Disconnect Script'),
            _('Script to run on disconnection.'));
        o.datatype = 'file';
        o.rmempty = true;
        o.placeholder = '/etc/ruhop/on-disconnect.sh';

        // Path Loss Detection (Probe)
        s = m.section(form.TypedSection, 'probe', _('Path Loss Detection'),
            _('Optional probe settings for detecting and blacklisting lossy paths.'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'probe_enabled', _('Enable Probing'),
            _('Enable path loss detection probes.'));
        o.default = '0';

        o = s.option(form.Value, 'probe_interval', _('Probe Interval'),
            _('Seconds between probes to each address.'));
        o.datatype = 'uinteger';
        o.default = '10';
        o.placeholder = '10';
        o.depends('probe_enabled', '1');

        o = s.option(form.Value, 'probe_threshold', _('Loss Threshold'),
            _('Loss rate threshold for blacklisting (0.0-1.0).'));
        o.datatype = 'ufloat';
        o.default = '0.5';
        o.placeholder = '0.5';
        o.depends('probe_enabled', '1');

        o = s.option(form.Value, 'probe_blacklist_duration', _('Blacklist Duration'),
            _('Seconds to keep address blacklisted.'));
        o.datatype = 'uinteger';
        o.default = '300';
        o.placeholder = '300';
        o.depends('probe_enabled', '1');

        o = s.option(form.Value, 'probe_min_probes', _('Minimum Probes'),
            _('Minimum probes before blacklist decision.'));
        o.datatype = 'uinteger';
        o.default = '3';
        o.placeholder = '3';
        o.depends('probe_enabled', '1');

        // Client DNS Proxy
        s = m.section(form.TypedSection, 'client_dns_proxy', _('Client DNS Proxy'),
            _('Optional local DNS proxy to forward queries through VPN.'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'dns_proxy_enabled', _('Enable DNS Proxy'),
            _('Enable local DNS proxy.'));
        o.default = '0';

        o = s.option(form.Value, 'dns_proxy_port', _('DNS Proxy Port'),
            _('Local port to listen for DNS queries.'));
        o.datatype = 'port';
        o.default = '53';
        o.placeholder = '53';
        o.depends('dns_proxy_enabled', '1');

        o = s.option(form.Flag, 'dns_proxy_filter_ipv6', _('Filter IPv6'),
            _('Filter AAAA records from DNS responses.'));
        o.default = '0';
        o.depends('dns_proxy_enabled', '1');

        o = s.option(form.Value, 'dns_proxy_ipset', _('IP Set Name'),
            _('Optional Linux IP set name for resolved addresses (nftables or ipset).'));
        o.datatype = 'string';
        o.rmempty = true;
        o.placeholder = 'ruhop_resolved';
        o.depends('dns_proxy_enabled', '1');

        return m.render();
    }
});
