'use strict';
'require view';
'require poll';
'require rpc';
'require ui';

var callRuhopStatus = rpc.declare({
    object: 'file',
    method: 'exec',
    params: ['command', 'params'],
    expect: { stdout: '' }
});

var callInitAction = rpc.declare({
    object: 'luci',
    method: 'setInitAction',
    params: ['name', 'action'],
    expect: { result: false }
});

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

return view.extend({
    load: function() {
        return Promise.all([
            L.resolveDefault(callRuhopStatus('/usr/bin/ruhop', ['status', '--json']), {}),
            L.resolveDefault(callRuhopStatus('/bin/pgrep', ['-x', 'ruhop']), {})
        ]);
    },

    pollStatus: function() {
        return Promise.all([
            L.resolveDefault(callRuhopStatus('/usr/bin/ruhop', ['status', '--json']), {}),
            L.resolveDefault(callRuhopStatus('/bin/pgrep', ['-x', 'ruhop']), {})
        ]);
    },

    render: function(data) {
        var status = {};
        var isRunning = data[1] && data[1].stdout && data[1].stdout.trim() !== '';

        if (data[0] && data[0].stdout) {
            try {
                status = JSON.parse(data[0].stdout);
            } catch (e) {
                status = {};
            }
        }

        var view = E('div', { 'class': 'cbi-map' }, [
            E('h2', {}, _('Ruhop VPN Status')),

            E('div', { 'class': 'cbi-section' }, [
                E('div', { 'class': 'cbi-section-node' }, [
                    E('div', { 'class': 'cbi-value' }, [
                        E('label', { 'class': 'cbi-value-title' }, _('Service Status')),
                        E('div', { 'class': 'cbi-value-field' }, [
                            E('span', {
                                'id': 'status-badge',
                                'class': isRunning ? 'badge badge-success' : 'badge badge-danger'
                            }, isRunning ? _('Running') : _('Stopped'))
                        ])
                    ])
                ])
            ]),

            E('div', { 'class': 'cbi-section' }, [
                E('h3', {}, _('Service Control')),
                E('div', { 'class': 'cbi-section-node' }, [
                    E('div', { 'class': 'cbi-value' }, [
                        E('div', { 'class': 'cbi-value-field' }, [
                            E('button', {
                                'class': 'cbi-button cbi-button-apply',
                                'click': ui.createHandlerFn(this, function() {
                                    return callInitAction('ruhop', 'start').then(function() {
                                        window.setTimeout(function() { location.reload(); }, 2000);
                                    });
                                })
                            }, _('Start')),
                            ' ',
                            E('button', {
                                'class': 'cbi-button cbi-button-reset',
                                'click': ui.createHandlerFn(this, function() {
                                    return callInitAction('ruhop', 'stop').then(function() {
                                        window.setTimeout(function() { location.reload(); }, 2000);
                                    });
                                })
                            }, _('Stop')),
                            ' ',
                            E('button', {
                                'class': 'cbi-button cbi-button-action',
                                'click': ui.createHandlerFn(this, function() {
                                    return callInitAction('ruhop', 'restart').then(function() {
                                        window.setTimeout(function() { location.reload(); }, 2000);
                                    });
                                })
                            }, _('Restart'))
                        ])
                    ])
                ])
            ]),

            E('div', { 'class': 'cbi-section' }, [
                E('h3', {}, _('Connection Details')),
                E('div', { 'class': 'cbi-section-node', 'id': 'status-details' }, [
                    isRunning && status.role ? E('table', { 'class': 'table' }, [
                        E('tr', {}, [E('td', {}, _('Role')), E('td', {}, status.role || '-')]),
                        E('tr', {}, [E('td', {}, _('State')), E('td', {}, status.state || '-')]),
                        E('tr', {}, [E('td', {}, _('Uptime')), E('td', {}, status.uptime || '-')]),
                        E('tr', {}, [E('td', {}, _('Tunnel IP')), E('td', {}, status.tunnel_ip || '-')]),
                        E('tr', {}, [E('td', {}, _('Peer IP')), E('td', {}, status.peer_ip || '-')]),
                        E('tr', {}, [E('td', {}, _('TUN Device')), E('td', {}, status.tun_device || '-')]),
                        E('tr', {}, [E('td', {}, _('RX')), E('td', {}, formatBytes(status.rx_bytes || 0) + ' (' + (status.rx_packets || 0) + ' packets)')]),
                        E('tr', {}, [E('td', {}, _('TX')), E('td', {}, formatBytes(status.tx_bytes || 0) + ' (' + (status.tx_packets || 0) + ' packets)')]),
                        status.role === 'server' ? E('tr', {}, [E('td', {}, _('Active Sessions')), E('td', {}, status.sessions || 0)]) : E([])
                    ]) : E('p', { 'class': 'alert-message info' }, isRunning ? _('Loading...') : _('Service is not running'))
                ])
            ]),

            E('style', {}, `
                .badge {
                    display: inline-block;
                    padding: 0.35em 0.65em;
                    font-size: 0.85em;
                    font-weight: 700;
                    line-height: 1;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: baseline;
                    border-radius: 0.375rem;
                }
                .badge-success {
                    background-color: #198754;
                    color: #fff;
                }
                .badge-danger {
                    background-color: #dc3545;
                    color: #fff;
                }
                .table {
                    width: 100%;
                    border-collapse: collapse;
                }
                .table td {
                    padding: 8px;
                    border-bottom: 1px solid #ddd;
                }
                .table td:first-child {
                    font-weight: bold;
                    width: 150px;
                }
            `)
        ]);

        return view;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
