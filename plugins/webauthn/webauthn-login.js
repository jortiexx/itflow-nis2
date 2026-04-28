// WebAuthn login flow for the agent MFA step.
// Loaded as an external file so the strict default-src 'self' CSP allows it.
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
        var btn = document.getElementById('webauthn_login_btn');
        if (!btn) return;
        btn.addEventListener('click', async function () {
            var status = document.getElementById('webauthn_login_status');
            status.textContent = 'Requesting challenge…';
            try {
                var r = await fetch('/login_webauthn_options.php', { credentials: 'same-origin' });
                if (!r.ok) throw new Error('options request failed: ' + r.status);
                var opts = await r.json();
                opts.challenge = b64uToBytes(opts.challenge);
                (opts.allowCredentials || []).forEach(function (c) { c.id = b64uToBytes(c.id); });

                status.textContent = 'Waiting for your security key…';
                var assertion = await navigator.credentials.get({ publicKey: opts });

                var payload = {
                    id: assertion.id,
                    rawId: bytesToB64u(assertion.rawId),
                    type: assertion.type,
                    response: {
                        clientDataJSON: bytesToB64u(assertion.response.clientDataJSON),
                        authenticatorData: bytesToB64u(assertion.response.authenticatorData),
                        signature: bytesToB64u(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? bytesToB64u(assertion.response.userHandle) : null
                    }
                };

                var fd = new FormData();
                fd.append('credential', JSON.stringify(payload));
                var verify = await fetch('/login_webauthn_verify.php', { method: 'POST', body: fd, credentials: 'same-origin' });
                var result = await verify.json();
                if (!verify.ok || result.error) {
                    status.innerHTML = '<span class="text-danger">' + (result.error || 'Sign-in failed') + '</span>';
                    return;
                }
                status.innerHTML = '<span class="text-success">Signed in. Redirecting…</span>';
                window.location = result.redirect || '/';
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
