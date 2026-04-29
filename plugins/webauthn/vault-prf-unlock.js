// Vault PRF unlock ceremony.
// Loaded from agent/vault_unlock.php when the user has at least one
// webauthn_prf method enrolled.
(function () {
    function b64uToBytes(b64u) {
        var pad = '='.repeat((4 - b64u.length % 4) % 4);
        var b64 = (b64u + pad).replace(/-/g, '+').replace(/_/g, '/');
        var raw = atob(b64);
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }
    function bytesToB64u(buf) {
        var b = new Uint8Array(buf);
        var s = '';
        for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function unlock() {
        var status = document.getElementById('vault_prf_unlock_status');
        status.textContent = 'Requesting challenge…';
        try {
            var r = await fetch('/agent/vault_unlock_prf_options.php', { credentials: 'same-origin' });
            if (!r.ok) {
                var err = await r.json().catch(function () { return {}; });
                throw new Error(err.error || ('options request failed: ' + r.status));
            }
            var opts = await r.json();
            opts.challenge = b64uToBytes(opts.challenge);
            (opts.allowCredentials || []).forEach(function (c) { c.id = b64uToBytes(c.id); });

            if (opts.extensions && opts.extensions.prf && opts.extensions.prf.evalByCredential) {
                var ebc = opts.extensions.prf.evalByCredential;
                Object.keys(ebc).forEach(function (k) {
                    ebc[k].first = b64uToBytes(ebc[k].first);
                });
            }

            status.textContent = 'Touch your security key…';
            var assertion = await navigator.credentials.get({ publicKey: opts });

            var ext = assertion.getClientExtensionResults();
            var prfRes = ext && ext.prf ? ext.prf : null;
            if (!prfRes || !prfRes.results || !prfRes.results.first) {
                throw new Error('Authenticator did not return a PRF output for this credential. Use the PIN fallback below.');
            }

            var payload = {
                id: assertion.id,
                rawId: bytesToB64u(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON:    bytesToB64u(assertion.response.clientDataJSON),
                    authenticatorData: bytesToB64u(assertion.response.authenticatorData),
                    signature:         bytesToB64u(assertion.response.signature),
                    userHandle:        assertion.response.userHandle ? bytesToB64u(assertion.response.userHandle) : null
                }
            };

            var fd = new FormData();
            fd.append('credential', JSON.stringify(payload));
            fd.append('prf_output', bytesToB64u(prfRes.results.first));

            var verify = await fetch('/agent/vault_unlock_prf_verify.php', {
                method: 'POST', body: fd, credentials: 'same-origin'
            });
            var result = await verify.json();
            if (!verify.ok || result.error) {
                status.innerHTML = '<span class="text-danger">' + (result.error || 'unlock failed') + '</span>';
                return;
            }
            status.innerHTML = '<span class="text-success">Vault unlocked. Redirecting…</span>';
            window.location = result.redirect || '/';
        } catch (e) {
            status.innerHTML = '<span class="text-danger">' + (e.message || e) + '</span>';
        }
    }

    function init() {
        var btn = document.getElementById('vault_prf_unlock_btn');
        if (!btn) return;
        btn.addEventListener('click', unlock);

        // Auto-start the ceremony if the user has elected to skip the click step.
        if (btn.dataset.autostart === '1') {
            unlock();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
