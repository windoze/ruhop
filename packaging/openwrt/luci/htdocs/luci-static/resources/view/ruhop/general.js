'use strict';
'require view';
'require form';
'require uci';
'require rpc';

var callServiceList = rpc.declare({
    object: 'service',
    method: 'list',
    params: ['name'],
    expect: { '': {} }
});

return view.extend({
    load: function() {
        return Promise.all([
            uci.load('ruhop'),
            callServiceList('ruhop')
        ]);
    },

    render: function(data) {
        var m, s, o;
        var isRunning = data[1] && data[1].ruhop && data[1].ruhop.instances &&
                       data[1].ruhop.instances.ruhop && data[1].ruhop.instances.ruhop.running;

        m = new form.Map('ruhop', _('Ruhop VPN - General Settings'),
            _('Ruhop is a UDP-based VPN with port hopping capabilities for traffic obfuscation.'));

        // Service Control Section
        s = m.section(form.TypedSection, 'ruhop', _('Service Control'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'enabled', _('Enable'));
        o.rmempty = false;

        o = s.option(form.ListValue, 'mode', _('Mode'));
        o.value('client', _('Client'));
        o.value('server', _('Server'));
        o.default = 'client';

        o = s.option(form.Value, 'config', _('Config File Path'));
        o.default = '/etc/ruhop/ruhop.toml';
        o.datatype = 'string';
        o.rmempty = false;

        // Common Settings Section
        s = m.section(form.TypedSection, 'common', _('Common Settings'),
            _('Settings shared between server and client modes.'));
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Value, 'key', _('Pre-shared Key'),
            _('Encryption key that must match between client and server.'));
        o.password = true;
        o.datatype = 'string';
        o.rmempty = false;

        o = s.option(form.Value, 'mtu', _('MTU'),
            _('Maximum Transmission Unit for the tunnel interface. Minimum: 576'));
        o.datatype = 'range(576,9000)';
        o.default = '1400';
        o.placeholder = '1400';

        o = s.option(form.ListValue, 'log_level', _('Log Level'));
        o.value('error', _('Error'));
        o.value('warn', _('Warning'));
        o.value('info', _('Info'));
        o.value('debug', _('Debug'));
        o.value('trace', _('Trace'));
        o.default = 'info';

        o = s.option(form.Value, 'log_file', _('Log File Directory'),
            _('Optional directory path for file-based logging.'));
        o.datatype = 'directory';
        o.rmempty = true;
        o.placeholder = '/var/log/ruhop';

        o = s.option(form.ListValue, 'log_rotation', _('Log Rotation'));
        o.value('hourly', _('Hourly'));
        o.value('daily', _('Daily'));
        o.value('never', _('Never'));
        o.default = 'daily';
        o.depends('log_file', /./);

        o = s.option(form.Flag, 'obfuscation', _('Packet Obfuscation'),
            _('Enable packet obfuscation with random noise bytes.'));
        o.default = '0';

        o = s.option(form.Value, 'heartbeat_interval', _('Heartbeat Interval'),
            _('Seconds between keep-alive packets.'));
        o.datatype = 'uinteger';
        o.default = '30';
        o.placeholder = '30';

        o = s.option(form.Value, 'tun_device', _('TUN Device Name'),
            _('Optional custom TUN device name. Defaults to \'ruhop\'.'));
        o.datatype = 'string';
        o.placeholder = 'ruhop';
        o.rmempty = true;

        o = s.option(form.ListValue, 'use_nftables', _('Firewall Backend'),
            _('Select firewall backend. OpenWRT with fw4 uses nftables.'));
        o.value('', _('Auto-detect'));
        o.value('1', _('nftables (fw4)'));
        o.value('0', _('iptables (fw3)'));
        o.default = '1';

        return m.render();
    }
});
