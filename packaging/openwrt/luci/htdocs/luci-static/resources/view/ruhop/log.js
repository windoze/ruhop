'use strict';
'require view';
'require poll';
'require rpc';
'require ui';

var callLogRead = rpc.declare({
    object: 'file',
    method: 'exec',
    params: ['command', 'params'],
    expect: { stdout: '' }
});

return view.extend({
    load: function() {
        return callLogRead('/usr/bin/logread', ['-e', 'ruhop']);
    },

    render: function(data) {
        var logContent = data && data.stdout ? data.stdout : _('No log entries found');
        var self = this;

        var view = E('div', { 'class': 'cbi-map' }, [
            E('h2', {}, _('Ruhop VPN Log')),

            E('div', { 'class': 'cbi-section' }, [
                E('div', { 'class': 'cbi-section-node' }, [
                    E('div', { 'class': 'cbi-value' }, [
                        E('label', { 'class': 'cbi-value-title' }, _('Lines to show')),
                        E('div', { 'class': 'cbi-value-field' }, [
                            E('select', {
                                'id': 'log-lines',
                                'class': 'cbi-input-select',
                                'change': ui.createHandlerFn(this, function() {
                                    self.refreshLog();
                                })
                            }, [
                                E('option', { 'value': '25' }, '25'),
                                E('option', { 'value': '50', 'selected': 'selected' }, '50'),
                                E('option', { 'value': '100' }, '100'),
                                E('option', { 'value': '200' }, '200'),
                                E('option', { 'value': '500' }, '500')
                            ])
                        ])
                    ]),
                    E('div', { 'class': 'cbi-value' }, [
                        E('div', { 'class': 'cbi-value-field' }, [
                            E('button', {
                                'class': 'cbi-button cbi-button-apply',
                                'click': ui.createHandlerFn(this, function() {
                                    self.refreshLog();
                                })
                            }, _('Refresh')),
                            ' ',
                            E('button', {
                                'class': 'cbi-button cbi-button-action',
                                'id': 'btn-auto-refresh',
                                'click': ui.createHandlerFn(this, function(ev) {
                                    self.toggleAutoRefresh(ev.target);
                                })
                            }, _('Auto-refresh')),
                            ' ',
                            E('button', {
                                'class': 'cbi-button cbi-button-reset',
                                'click': ui.createHandlerFn(this, function() {
                                    document.getElementById('log-content').value = '';
                                })
                            }, _('Clear'))
                        ])
                    ])
                ])
            ]),

            E('div', { 'class': 'cbi-section' }, [
                E('div', { 'class': 'cbi-section-node' }, [
                    E('textarea', {
                        'id': 'log-content',
                        'readonly': 'readonly',
                        'wrap': 'off',
                        'style': 'width:100%; height:500px; font-family:monospace; font-size:12px; background:#1e1e1e; color:#d4d4d4; padding:10px; border:1px solid #444; resize:vertical;'
                    }, this.truncateLog(logContent, 50))
                ])
            ])
        ]);

        return view;
    },

    truncateLog: function(log, lines) {
        if (!log) return '';
        var logLines = log.split('\n');
        if (logLines.length > lines) {
            return logLines.slice(-lines).join('\n');
        }
        return log;
    },

    refreshLog: function() {
        var self = this;
        var lines = document.getElementById('log-lines').value;

        callLogRead('/usr/bin/logread', ['-e', 'ruhop']).then(function(data) {
            var textarea = document.getElementById('log-content');
            if (textarea && data && data.stdout) {
                textarea.value = self.truncateLog(data.stdout, parseInt(lines));
                textarea.scrollTop = textarea.scrollHeight;
            }
        });
    },

    toggleAutoRefresh: function(btn) {
        var self = this;

        if (this._autoRefreshInterval) {
            clearInterval(this._autoRefreshInterval);
            this._autoRefreshInterval = null;
            btn.textContent = _('Auto-refresh');
            btn.className = 'cbi-button cbi-button-action';
        } else {
            this._autoRefreshInterval = setInterval(function() {
                self.refreshLog();
            }, 3000);
            btn.textContent = _('Stop Auto-refresh');
            btn.className = 'cbi-button cbi-button-reset';
        }
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
