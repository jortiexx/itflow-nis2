// Vault PRF enrollment ceremony.
// Loaded from agent/user/user_security.php after the user clicks "Add hardware unlock".
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

    function init() {
        var btn = document.getElementById('vault_prf_enroll_btn');
        if (!btn) return;

        btn.addEventListener('click', async function () {
            var status = document.getElementById('vault_prf_enroll_status');
            status.textContent = 'Requesting registration challenge…';
            try {
                var r = await fetch('webauthn_prf_register_options.php', { credentials: 'same-origin' });
                if (!r.ok) {
                    var err = await r.json().catch(function () { return {}; });
                    throw new Error(err.error || ('options request failed: ' + r.status));
                }
                var opts = await r.json();
                opts.challenge = b64uToBytes(opts.challenge);
                opts.user.id = b64uToBytes(opts.user.id);
                (opts.excludeCredentials || []).forEach(function (c) { c.id = b64uToBytes(c.id); });

                if (opts.extensions && opts.extensions.prf && opts.extensions.prf.eval && opts.extensions.prf.eval.first) {
                    opts.extensions.prf.eval.first = b64uToBytes(opts.extensions.prf.eval.first);
                }

                status.textContent = 'Touch your security key…';
                var cred = await navigator.credentials.create({ publicKey: opts });

                var ext = cred.getClientExtensionResults();
                var prfRes = ext && ext.prf ? ext.prf : null;
                if (!prfRes || !prfRes.results || !prfRes.results.first) {
                    if (prfRes && prfRes.enabled === true) {
                        throw new Error('Authenticator supports PRF but did not evaluate during registration. Try a different browser or authenticator (Chrome / Edge / Firefox 122+ recommended).');
                    }
                    throw new Error('Your authenticator does not support the WebAuthn PRF extension. Pick a security key that supports it (YubiKey 5 firmware 5.2.3+, Windows Hello, Touch ID, recent platform passkeys).');
                }

                var payload = {
                    id: cred.id,
                    rawId: bytesToB64u(cred.rawId),
                    type: cred.type,
                    response: {
                        clientDataJSON:    bytesToB64u(cred.response.clientDataJSON),
                        attestationObject: bytesToB64u(cred.response.attestationObject)
                    }
                };

                var fd = new FormData();
                fd.append('csrf_token', document.getElementById('vault_prf_csrf').value);
                fd.append('credential', JSON.stringify(payload));
                fd.append('prf_output', bytesToB64u(prfRes.results.first));
                fd.append('label', document.getElementById('vault_prf_label').value || '');

                var verify = await fetch('webauthn_prf_register_verify.php', {
                    method: 'POST', body: fd, credentials: 'same-origin'
                });
                var result = await verify.json();
                if (!verify.ok || result.error) {
                    status.innerHTML = '<span class="text-danger">' + (result.error || 'registration failed') + '</span>';
                    return;
                }
                status.innerHTML = '<span class="text-success">Hardware unlock enrolled. Reload to see it in the list.</span>';
                setTimeout(function () { location.reload(); }, 1500);
            } catch (e) {
                status.innerHTML = '<span class="text-danger">' + (e.message || e) + '</span>';
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
