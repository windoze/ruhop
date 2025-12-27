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

        m = new form.Map('ruhop', _('Ruhop VPN - Server Mode'),
            _('Configure ruhop as a VPN server.'));

        // Server Settings Section
        s = m.section(form.TypedSection, 'server', _('Server Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Value, 'listen', _('Listen Address'),
            _('IP address to bind to. Use 0.0.0.0 for all interfaces.'));
        o.datatype = 'ipaddr';
        o.default = '0.0.0.0';
        o.rmempty = false;

        o = s.option(form.Value, 'port_start', _('Port Range Start'),
            _('Starting port for port hopping range.'));
        o.datatype = 'port';
        o.default = '4096';
        o.rmempty = false;

        o = s.option(form.Value, 'port_end', _('Port Range End'),
            _('Ending port for port hopping range.'));
        o.datatype = 'port';
        o.default = '4196';
        o.rmempty = false;

        o = s.option(form.Value, 'tunnel_network', _('Tunnel Network'),
            _('CIDR notation network for client IP allocation (e.g., 10.0.0.0/24).'));
        o.datatype = 'cidr4';
        o.default = '10.0.0.0/24';
        o.rmempty = false;

        o = s.option(form.Value, 'tunnel_ip', _('Server Tunnel IP'),
            _('Optional server\'s tunnel IP. Defaults to network_address + 1 if not set.'));
        o.datatype = 'ip4addr';
        o.placeholder = '10.0.0.1';
        o.rmempty = true;

        o = s.option(form.Value, 'max_clients', _('Maximum Clients'),
            _('Maximum number of concurrent client connections.'));
        o.datatype = 'uinteger';
        o.default = '100';
        o.placeholder = '100';

        // NAT Settings
        s = m.section(form.TypedSection, 'server', _('NAT Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'enable_nat', _('Enable NAT'),
            _('Enable NAT/masquerading for client traffic.'));
        o.default = '1';

        o = s.option(form.Value, 'nat_interface', _('NAT Interface'),
            _('Outbound interface for NAT. Auto-detected if not set.'));
        o.datatype = 'string';
        o.placeholder = 'eth0';
        o.rmempty = true;
        o.depends('enable_nat', '1');

        // DNS Proxy Settings
        s = m.section(form.TypedSection, 'server', _('DNS Proxy Settings'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'dns_proxy', _('Enable DNS Proxy'),
            _('Enable DNS proxy on tunnel IP for clients.'));
        o.default = '0';

        o = s.option(form.DynamicList, 'dns_servers', _('Upstream DNS Servers'),
            _('DNS servers to forward queries to. Formats: IP, IP:port, IP/udp, IP/tcp, https://..., tls://...'));
        o.datatype = 'string';
        o.placeholder = '8.8.8.8';
        o.depends('dns_proxy', '1');

        return m.render();
    }
});
