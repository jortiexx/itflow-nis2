<?php

// Role check failed wording
DEFINE("WORDING_ROLECHECK_FAILED", "You are not permitted to do that!");

// Function to generate both crypto & URL safe random strings
function randomString(int $length = 16): string {
    $bytes = random_bytes((int) ceil($length * 3 / 4));
    return substr(
        rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='),
        0,
        $length
    );
}

// Older keygen function - only used for TOTP currently
function key32gen() {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $chars .= "234567";
    while (1) {
        $key = '';
        srand((float) microtime() * 1000000);
        for ($i = 0; $i < 32; $i++) {
            $key .= substr($chars, (rand() % (strlen($chars))), 1);
        }
        break;
    }
    return $key;
}

function nullable_htmlentities($unsanitizedInput) {
    //return htmlentities($unsanitizedInput ?? '');
    return htmlspecialchars($unsanitizedInput ?? '', ENT_QUOTES, 'UTF-8');
}

function initials($string) {
    if (!empty($string)) {
        $return = '';
        foreach (explode(' ', $string) as $word) {
            $return .= mb_strtoupper($word[0], 'UTF-8'); // Use mb_strtoupper for UTF-8 support
        }
        $return = substr($return, 0, 2);
        return $return;
    }
}

function removeDirectory($path) {
    if (!file_exists($path)) {
        return;
    }

    $files = glob($path . '/*');
    foreach ($files as $file) {
        is_dir($file) ? removeDirectory($file) : unlink($file);
    }
    rmdir($path);
}

function copyDirectory($src, $dst) {
    if (!is_dir($src)) {
        return;
    }

    if (!is_dir($dst)) {
        mkdir($dst, 0775, true);
    }

    $items = scandir($src);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $srcPath = $src . '/' . $item;
        $dstPath = $dst . '/' . $item;

        if (is_dir($srcPath)) {
            copyDirectory($srcPath, $dstPath);
        } else {
            copy($srcPath, $dstPath);
        }
    }
}

function getUserAgent() {
    return $_SERVER['HTTP_USER_AGENT'];
}

function getIP() {

    // Default way to get IP
    $ip = $_SERVER['REMOTE_ADDR'];

    // Allow overrides via config.php in-case we use a proxy - https://docs.itflow.org/config_php
    if (defined("CONST_GET_IP_METHOD") && CONST_GET_IP_METHOD == "HTTP_X_FORWARDED_FOR") {
        $ip = explode(',', getenv('HTTP_X_FORWARDED_FOR'))[0] ?? $_SERVER['REMOTE_ADDR'];
    } elseif (defined("CONST_GET_IP_METHOD") && CONST_GET_IP_METHOD == "HTTP_CF_CONNECTING_IP") {
        $ip = $_SERVER["HTTP_CF_CONNECTING_IP"] ?? $_SERVER['REMOTE_ADDR'];
    }

    // Abort if something isn't right
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        error_log("ITFlow - Could not validate remote IP address");
        error_log("ITFlow - IP was [$ip] using method " . CONST_GET_IP_METHOD);
        exit("Potential Security Violation");
    }

    return $ip;
}

function getWebBrowser($user_browser) {
    $browser        =   "-";
    $browser_array  =   array(
        '/msie/i'       =>  "<i class='fab fa-fw fa-internet-explorer text-secondary'></i> Internet Explorer",
        '/firefox/i'    =>  "<i class='fab fa-fw fa-firefox text-secondary'></i> Firefox",
        '/safari/i'     =>  "<i class='fab fa-fw fa-safari text-secondary'></i> Safari",
        '/chrome/i'     =>  "<i class='fab fa-fw fa-chrome text-secondary'></i> Chrome",
        '/edg/i'        =>  "<i class='fab fa-fw fa-edge text-secondary'></i> Edge",
        '/opr/i'        =>  "<i class='fab fa-fw fa-opera text-secondary'></i> Opera",
        '/ddg/i'        =>  "<i class='fas fa-fw fa-globe text-secondary'></i> DuckDuckGo"
    );
    foreach ($browser_array as $regex => $value) {
        if (preg_match($regex, $user_browser)) {
            $browser    =   $value;
        }
    }
    return $browser;
}

function getOS($user_os) {
    $os_platform    =   "-";
    $os_array       =   array(
        '/windows/i'            =>  "<i class='fab fa-fw fa-windows text-secondary'></i> Windows",
        '/macintosh|mac os x/i' =>  "<i class='fab fa-fw fa-apple text-secondary'></i> MacOS",
        '/linux/i'              =>  "<i class='fab fa-fw fa-linux text-secondary'></i> Linux",
        '/ubuntu/i'             =>  "<i class='fab fa-fw fa-ubuntu text-secondary'></i> Ubuntu",
        '/fedora/i'             =>  "<i class='fab fa-fw fa-fedora text-secondary'></i> Fedora",
        '/iphone/i'             =>  "<i class='fab fa-fw fa-apple text-secondary'></i> iPhone",
        '/ipad/i'               =>  "<i class='fab fa-fw fa-apple text-secondary'></i> iPad",
        '/android/i'            =>  "<i class='fab fa-fw fa-android text-secondary'></i> Android"
    );
    foreach ($os_array as $regex => $value) {
        if (preg_match($regex, $user_os)) {
            $os_platform    =   $value;
        }
    }
    return $os_platform;
}

function getDevice() {
    $tablet_browser = 0;
    $mobile_browser = 0;
    if (preg_match('/(tablet|ipad|playbook)|(android(?!.*(mobi|opera mini)))/i', strtolower($_SERVER['HTTP_USER_AGENT']))) {
        $tablet_browser++;
    }
    if (preg_match('/(up.browser|up.link|mmp|symbian|smartphone|midp|wap|phone|android|iemobile)/i', strtolower($_SERVER['HTTP_USER_AGENT']))) {
        $mobile_browser++;
    }
    if ((strpos(strtolower($_SERVER['HTTP_ACCEPT']), 'application/vnd.wap.xhtml+xml') > 0) || ((isset($_SERVER['HTTP_X_WAP_PROFILE']) || isset($_SERVER['HTTP_PROFILE'])))) {
        $mobile_browser++;
    }
    $mobile_ua = strtolower(substr(getUserAgent(), 0, 4));
    $mobile_agents = array(
        'w3c ', 'acs-', 'alav', 'alca', 'amoi', 'audi', 'avan', 'benq', 'bird', 'blac',
        'blaz', 'brew', 'cell', 'cldc', 'cmd-', 'dang', 'doco', 'eric', 'hipt', 'inno',
        'ipaq', 'java', 'jigs', 'kddi', 'keji', 'leno', 'lg-c', 'lg-d', 'lg-g', 'lge-',
        'maui', 'maxo', 'midp', 'mits', 'mmef', 'mobi', 'mot-', 'moto', 'mwbp', 'nec-',
        'newt', 'noki', 'palm', 'pana', 'pant', 'phil', 'play', 'port', 'prox',
        'qwap', 'sage', 'sams', 'sany', 'sch-', 'sec-', 'send', 'seri', 'sgh-', 'shar',
        'sie-', 'siem', 'smal', 'smar', 'sony', 'sph-', 'symb', 't-mo', 'teli', 'tim-',
        'tosh', 'tsm-', 'upg1', 'upsi', 'vk-v', 'voda', 'wap-', 'wapa', 'wapi', 'wapp',
        'wapr', 'webc', 'winw', 'winw', 'xda ', 'xda-'
    );
    if (in_array($mobile_ua, $mobile_agents)) {
        $mobile_browser++;
    }
    if (strpos(strtolower(getUserAgent()), 'opera mini') > 0) {
        $mobile_browser++;
        //Check for tablets on Opera Mini alternative headers
        $stock_ua = strtolower(isset($_SERVER['HTTP_X_OPERAMINI_PHONE_UA']) ? $_SERVER['HTTP_X_OPERAMINI_PHONE_UA'] : (isset($_SERVER['HTTP_DEVICE_STOCK_UA']) ? $_SERVER['HTTP_DEVICE_STOCK_UA'] : ''));
        if (preg_match('/(tablet|ipad|playbook)|(android(?!.*mobile))/i', $stock_ua)) {
            $tablet_browser++;
        }
    }
    if ($tablet_browser > 0) {
        //do something for tablet devices
        return 'Tablet';
    } else if ($mobile_browser > 0) {
        //do something for mobile devices
        return 'Mobile';
    } else {
        //do something for everything else
        return 'Computer';
    }
}

function truncate($text, $chars) {
    if (strlen($text) <= $chars) {
        return $text;
    }
    $text = $text . " ";
    $text = substr($text, 0, $chars);
    $lastSpacePos = strrpos($text, ' ');
    if ($lastSpacePos !== false) {
        $text = substr($text, 0, $lastSpacePos);
    }
    return $text . "...";
}

function formatPhoneNumber($phoneNumber, $country_code = '', $show_country_code = false) {
    // Remove all non-digit characters
    $digits = preg_replace('/\D/', '', $phoneNumber ?? '');
    $formatted = '';

    // If no digits at all, fallback early
    if (strlen($digits) === 0) {
        return $phoneNumber;
    }

    // Helper function to safely check the first digit
    $startsWith = function($str, $char) {
        return isset($str[0]) && $str[0] === $char;
    };

    switch ($country_code) {
        case '1': // USA/Canada
            if (strlen($digits) === 10) {
                $formatted = '(' . substr($digits, 0, 3) . ') ' . substr($digits, 3, 3) . '-' . substr($digits, 6);
            }
            break;

        case '44': // UK
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) === 10) {
                $formatted = '0' . substr($digits, 0, 4) . ' ' . substr($digits, 4, 3) . ' ' . substr($digits, 7);
            }
            break;

        case '61': // Australia
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) === 9) {
                $formatted = '0' . substr($digits, 0, 4) . ' ' . substr($digits, 4, 3) . ' ' . substr($digits, 7);
            }
            break;

        case '91': // India
            if (strlen($digits) === 10) {
                $formatted = substr($digits, 0, 5) . ' ' . substr($digits, 5);
            }
            break;

        case '81': // Japan
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) >= 9 && strlen($digits) <= 10) {
                $formatted = '0' . substr($digits, 0, 2) . '-' . substr($digits, 2, 4) . '-' . substr($digits, 6);
            }
            break;

        case '49': // Germany
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) >= 10) {
                $formatted = '0' . substr($digits, 0, 3) . ' ' . substr($digits, 3);
            }
            break;

        case '33': // France
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) === 9) {
                $formatted = '0' . implode(' ', str_split($digits, 2));
            }
            break;

        case '34': // Spain
            if (strlen($digits) === 9) {
                $formatted = substr($digits, 0, 3) . ' ' . substr($digits, 3, 3) . ' ' . substr($digits, 6);
            }
            break;

        case '39': // Italy
            if ($startsWith($digits, '0')) {
                $digits = substr($digits, 1);
            }
            $formatted = '0' . implode(' ', str_split($digits, 3));
            break;

        case '55': // Brazil
            if (strlen($digits) === 11) {
                $formatted = '(' . substr($digits, 0, 2) . ') ' . substr($digits, 2, 5) . '-' . substr($digits, 7);
            }
            break;

        case '7': // Russia
            if ($startsWith($digits, '8')) {
                $digits = substr($digits, 1);
            }
            if (strlen($digits) === 10) {
                $formatted = '8 (' . substr($digits, 0, 3) . ') ' . substr($digits, 3, 3) . '-' . substr($digits, 6, 2) . '-' . substr($digits, 8);
            }
            break;

        case '86': // China
            if (strlen($digits) === 11) {
                $formatted = substr($digits, 0, 3) . ' ' . substr($digits, 3, 4) . ' ' . substr($digits, 7);
            }
            break;

        case '82': // South Korea
            if (strlen($digits) === 11) {
                $formatted = substr($digits, 0, 3) . '-' . substr($digits, 3, 4) . '-' . substr($digits, 7);
            }
            break;

        case '62': // Indonesia
            if (!$startsWith($digits, '0')) {
                $digits = '0' . $digits;
            }
            if (strlen($digits) === 12) {
                $formatted = substr($digits, 0, 4) . ' ' . substr($digits, 4, 4) . ' ' . substr($digits, 8);
            }
            break;

        case '63': // Philippines
            if (strlen($digits) === 11) {
                $formatted = substr($digits, 0, 4) . ' ' . substr($digits, 4, 3) . ' ' . substr($digits, 7);
            }
            break;

        case '234': // Nigeria
            if (!$startsWith($digits, '0')) {
                $digits = '0' . $digits;
            }
            if (strlen($digits) === 11) {
                $formatted = substr($digits, 0, 4) . ' ' . substr($digits, 4, 3) . ' ' . substr($digits, 7);
            }
            break;

        case '27': // South Africa
            if (strlen($digits) >= 9 && strlen($digits) <= 10) {
                $formatted = substr($digits, 0, 3) . ' ' . substr($digits, 3, 3) . ' ' . substr($digits, 6);
            }
            break;

        case '971': // UAE
            if (strlen($digits) === 9) {
                $formatted = substr($digits, 0, 3) . ' ' . substr($digits, 3, 3) . ' ' . substr($digits, 6);
            }
            break;

        default:
            // fallback — do nothing, use raw digits later
            break;
    }

    if (!$formatted) {
        $formatted = $digits ?: $phoneNumber;
    }

    return $show_country_code && $country_code ? "+$country_code $formatted" : $formatted;
}

function mkdirMissing($dir) {
    if (!is_dir($dir)) {
        mkdir($dir);
    }
}

// Called during initial setup
// Encrypts the master key with the user's password
function setupFirstUserSpecificKey($user_password, $site_encryption_master_key) {
    if (!is_string($site_encryption_master_key) || strlen($site_encryption_master_key) !== 16) {
        throw new RuntimeException(
            'setupFirstUserSpecificKey: site_encryption_master_key must be exactly 16 bytes, got '
            . (is_string($site_encryption_master_key) ? strlen($site_encryption_master_key) : gettype($site_encryption_master_key))
        );
    }

    // Use random_bytes(16) directly so the IV/salt sizes are guaranteed,
    // independent of randomString()'s default-length contract.
    $iv   = random_bytes(16);
    $salt = random_bytes(16);

    //Generate 128-bit (16 byte/char) kdhash of the users password
    $user_password_kdhash = hash_pbkdf2('sha256', $user_password, $salt, 100000, 16);

    //Encrypt the master key with the users kdf'd hash and the IV
    $ciphertext = openssl_encrypt($site_encryption_master_key, 'aes-128-cbc', $user_password_kdhash, 0, $iv);
    if ($ciphertext === false) {
        throw new RuntimeException('setupFirstUserSpecificKey: openssl_encrypt failed');
    }

    $wrapped = $salt . $iv . $ciphertext;

    // Self-verify the round-trip before returning. If anything went sideways
    // (truncated IV, libsodium glitch, etc.) we catch it here instead of
    // writing garbage to the database.
    $verify = openssl_decrypt(
        substr($wrapped, 32), 'aes-128-cbc',
        hash_pbkdf2('sha256', $user_password, substr($wrapped, 0, 16), 100000, 16),
        0,
        substr($wrapped, 16, 16)
    );
    if ($verify !== $site_encryption_master_key) {
        throw new RuntimeException('setupFirstUserSpecificKey: round-trip self-verify failed; refusing to return malformed wrapping');
    }

    return $wrapped;
}

/*
 * For additional users / password changes (and now the API)
 * New Users: Requires the admin setting up their account have a Specific/Session key configured
 * Password Changes: Will use the current info in the session.
*/
function encryptUserSpecificKey($user_password) {
    // Get the session info.
    $user_encryption_session_ciphertext = $_SESSION['user_encryption_session_ciphertext'] ?? null;
    $user_encryption_session_iv         = $_SESSION['user_encryption_session_iv']         ?? null;
    $user_encryption_session_key        = $_COOKIE['user_encryption_session_key']         ?? null;

    if (empty($user_encryption_session_ciphertext) || empty($user_encryption_session_iv) || empty($user_encryption_session_key)) {
        throw new RuntimeException('encryptUserSpecificKey: vault is locked (no session encryption material)');
    }

    // Decrypt the session key to get the master key
    $site_encryption_master_key = openssl_decrypt($user_encryption_session_ciphertext, 'aes-128-cbc', $user_encryption_session_key, 0, $user_encryption_session_iv);
    if ($site_encryption_master_key === false || strlen($site_encryption_master_key) !== 16) {
        throw new RuntimeException('encryptUserSpecificKey: could not retrieve a valid master key from session');
    }

    $iv   = random_bytes(16);
    $salt = random_bytes(16);

    // Generate 128-bit (16 byte/char) kdhash of the users (new) password
    $user_password_kdhash = hash_pbkdf2('sha256', $user_password, $salt, 100000, 16);

    // Encrypt the master key with the users kdf'd hash and the IV
    $ciphertext = openssl_encrypt($site_encryption_master_key, 'aes-128-cbc', $user_password_kdhash, 0, $iv);
    if ($ciphertext === false) {
        throw new RuntimeException('encryptUserSpecificKey: openssl_encrypt failed');
    }

    $wrapped = $salt . $iv . $ciphertext;

    // Self-verify the round-trip; refuse to return a malformed wrapping.
    $verify = openssl_decrypt(
        substr($wrapped, 32), 'aes-128-cbc',
        hash_pbkdf2('sha256', $user_password, substr($wrapped, 0, 16), 100000, 16),
        0,
        substr($wrapped, 16, 16)
    );
    if ($verify !== $site_encryption_master_key) {
        throw new RuntimeException('encryptUserSpecificKey: round-trip self-verify failed; refusing to return malformed wrapping');
    }

    return $wrapped;
}

// Given a ciphertext (incl. IV) and the user's (or API key) password, returns the site master key
// Ran at login, to facilitate generateUserSessionKey
function decryptUserSpecificKey($user_encryption_ciphertext, $user_password)
{
    // Detect malformed wrappings early. Historically, some hand-rolled setup
    // commands captured PHP warning text into this column (the "IV passed
    // is 32 bytes long..." pattern), which then silently failed every login
    // with no signal beyond a locked vault. Catch obvious garbage here.
    if (!is_string($user_encryption_ciphertext) || strlen($user_encryption_ciphertext) < 33) {
        error_log('decryptUserSpecificKey: wrapping is too short or non-string; vault cannot be unlocked');
        return false;
    }
    if (str_starts_with(ltrim($user_encryption_ciphertext), 'Warning:')
        || str_starts_with(ltrim($user_encryption_ciphertext), 'Notice:')) {
        error_log('decryptUserSpecificKey: wrapping starts with a PHP warning/notice — column was corrupted at write time. Use scripts/reset_master_key.php to recover.');
        return false;
    }

    //Get the IV, salt and ciphertext
    $salt = substr($user_encryption_ciphertext, 0, 16);
    $iv = substr($user_encryption_ciphertext, 16, 16);
    $ciphertext = substr($user_encryption_ciphertext, 32);

    //Generate 128-bit (16 byte/char) kdhash of the users password
    $user_password_kdhash = hash_pbkdf2('sha256', $user_password, $salt, 100000, 16);

    //Use this hash to get the original/master key
    $pt = openssl_decrypt($ciphertext, 'aes-128-cbc', $user_password_kdhash, 0, $iv);
    if ($pt === false) {
        error_log('decryptUserSpecificKey: openssl_decrypt failed — wrong password, or v1 wrapping is corrupt. Use scripts/reset_master_key.php to recover.');
    }
    return $pt;
}

/*
Generates what is probably best described as a session key (ephemeral-ish)
- Allows us to store the master key on the server whilst the user is using the application, without prompting to type their password everytime they want to decrypt a credential
- Ciphertext/IV is stored on the server in the users' session, encryption key is controlled/provided by the user as a cookie
- Only the user can decrypt their session ciphertext to get the master key
- Encryption key never hits the disk in cleartext
*/
function generateUserSessionKey($site_encryption_master_key)
{
    $user_encryption_session_key = randomString();
    $user_encryption_session_iv = randomString();
    $user_encryption_session_ciphertext = openssl_encrypt($site_encryption_master_key, 'aes-128-cbc', $user_encryption_session_key, 0, $user_encryption_session_iv);

    // Store ciphertext in the user's session
    $_SESSION['user_encryption_session_ciphertext'] = $user_encryption_session_ciphertext;
    $_SESSION['user_encryption_session_iv'] = $user_encryption_session_iv;

    // Give the user "their" key as a cookie
    include 'config.php';

    if ($config_https_only) {
        setcookie("user_encryption_session_key", "$user_encryption_session_key", ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'None']);
    } else {
        setcookie("user_encryption_session_key", $user_encryption_session_key, 0, "/");
        $_SESSION['alert_message'] = "Unencrypted connection flag set: Using non-secure cookies.";
    }
}

// Decrypts an encrypted password (website/asset credentials), returns it as a string.
// Reads v3 ("v3:..." prefix, per-client AES-256-GCM), v2 ("v2:..." shared AES-256-GCM)
// and legacy v1 (AES-128-CBC).
//
// $client_id is optional and only required for v3 ciphertexts. Callers that have
// the credential row should pass $row['credential_client_id']; older call sites
// without that context will still read v1/v2 correctly.
function decryptCredentialEntry($credential_password_ciphertext, $client_id = null)
{
    global $mysqli;

    // v3 path: per-client master key
    if (isCredentialV3($credential_password_ciphertext)) {
        if (!$client_id) {
            error_log('decryptCredentialEntry: v3 ciphertext without client_id');
            return false;
        }

        // Phase 10: prefer the user's per-user grant over the shared-master
        // fallback. A grant means cryptographic compartmentalisation —
        // this user really has the right to read this client's data.
        $client_master = getClientMasterKeyViaGrant(intval($client_id), $mysqli);
        if ($client_master === null) {
            // Fallback during migration: users without a grant yet still
            // need to read credentials. ensureClientMasterKey uses the
            // session shared master key.
            $client_master = ensureClientMasterKey(intval($client_id), $mysqli);
        }
        if ($client_master === null) {
            return false;
        }
        try {
            return decryptCredentialEntryV3($credential_password_ciphertext, $client_master);
        } catch (Throwable $e) {
            return false;
        }
    }

    // Get the user session info.
    $user_encryption_session_ciphertext = $_SESSION['user_encryption_session_ciphertext'] ?? null;
    $user_encryption_session_iv         = $_SESSION['user_encryption_session_iv']         ?? null;
    $user_encryption_session_key        = $_COOKIE['user_encryption_session_key']         ?? null;

    if (!$user_encryption_session_ciphertext || !$user_encryption_session_iv || !$user_encryption_session_key) {
        return false;
    }

    // Decrypt the session key to get the master key (still AES-128-CBC at session layer)
    $site_encryption_master_key = openssl_decrypt(
        $user_encryption_session_ciphertext, 'aes-128-cbc',
        $user_encryption_session_key, 0, $user_encryption_session_iv
    );

    if ($site_encryption_master_key === false) {
        return false;
    }

    // v2 path
    if (isCredentialV2($credential_password_ciphertext)) {
        try {
            return decryptCredentialEntryV2($credential_password_ciphertext, $site_encryption_master_key);
        } catch (Throwable $e) {
            return false;
        }
    }

    // Legacy v1 path
    $credential_iv         = substr($credential_password_ciphertext, 0, 16);
    $credential_ciphertext = substr($credential_password_ciphertext, 16);
    return openssl_decrypt(
        $credential_ciphertext, 'aes-128-cbc',
        $site_encryption_master_key, 0, $credential_iv
    );
}

// Encrypts a website/asset credential password.
// When $client_id is provided, uses the per-client master key (v3 format).
// Otherwise falls back to the shared master key (v2 format) for backward
// compatibility with callers that do not yet pass client context.
function encryptCredentialEntry($credential_password_cleartext, $client_id = null)
{
    global $mysqli;

    // v3 path: per-client master key
    if ($client_id && intval($client_id) > 0) {
        // Phase 10: prefer the user's per-user grant.
        $client_master = getClientMasterKeyViaGrant(intval($client_id), $mysqli);
        if ($client_master === null) {
            // Migration fallback: lazy-create / fetch via shared-master.
            $client_master = ensureClientMasterKey(intval($client_id), $mysqli);
            if ($client_master !== null) {
                // We just minted (or fetched via shared master). Take the
                // opportunity to materialise a per-user grant for the
                // current user so subsequent reads use the compartmentalised
                // path.
                materialiseGrantForCurrentUser(intval($client_id), $client_master, $mysqli);
            }
        }
        if ($client_master !== null) {
            return encryptCredentialEntryV3($credential_password_cleartext, $client_master);
        }
        // Fall through to v2 if the per-client key could not be obtained
        // (e.g. vault locked). Better to write v2 than to lose the value.
    }

    // Get the user session info.
    $user_encryption_session_ciphertext = $_SESSION['user_encryption_session_ciphertext'] ?? null;
    $user_encryption_session_iv         = $_SESSION['user_encryption_session_iv']         ?? null;
    $user_encryption_session_key        = $_COOKIE['user_encryption_session_key']         ?? null;

    if (!$user_encryption_session_ciphertext || !$user_encryption_session_iv || !$user_encryption_session_key) {
        return false;
    }

    $site_encryption_master_key = openssl_decrypt(
        $user_encryption_session_ciphertext, 'aes-128-cbc',
        $user_encryption_session_key, 0, $user_encryption_session_iv
    );

    if ($site_encryption_master_key === false) {
        return false;
    }

    return encryptCredentialEntryV2($credential_password_cleartext, $site_encryption_master_key);
}

/**
 * Unlock the master key for an API key.
 *
 * Mirrors unlockUserMasterKey but for the api_keys table:
 *  - Tries v2 wrapping first (Argon2id + AES-256-GCM in api_key_decrypt_hash_v2)
 *  - Falls back to v1 (PBKDF2 + AES-128-CBC in api_key_decrypt_hash)
 *  - Lazy-migrates v1 to v2 on the first successful v1 unwrap, so subsequent
 *    calls take the v2 path
 *
 * @param array $api_key_row Row from api_keys table; must have api_key_id,
 *                           api_key_decrypt_hash, api_key_decrypt_hash_v2.
 * @return string|null Master key bytes (16) on success, null on failure.
 */
function apiUnlockMasterKey(array $api_key_row, #[\SensitiveParameter] string $password, mysqli $mysqli): ?string
{
    $api_key_id = intval($api_key_row['api_key_id'] ?? 0);

    if (!empty($api_key_row['api_key_decrypt_hash_v2'])) {
        try {
            return decryptUserSpecificKeyV2(
                $api_key_row['api_key_decrypt_hash_v2'],
                $password
            );
        } catch (Throwable $e) {
            error_log("apiUnlockMasterKey: v2 unwrap failed for api_key_id=$api_key_id: " . $e->getMessage());
            return null;
        }
    }

    if (!empty($api_key_row['api_key_decrypt_hash'])) {
        $master_key = decryptUserSpecificKey(
            $api_key_row['api_key_decrypt_hash'],
            $password
        );
        if ($master_key === false || $master_key === '' || strlen($master_key) !== 16) {
            error_log("apiUnlockMasterKey: v1 unwrap failed for api_key_id=$api_key_id");
            return null;
        }
        try {
            $v2 = encryptUserSpecificKeyV2($master_key, $password);
            $v2_e = mysqli_real_escape_string($mysqli, $v2);
            mysqli_query(
                $mysqli,
                "UPDATE api_keys
                 SET api_key_decrypt_hash_v2 = '$v2_e'
                 WHERE api_key_id = $api_key_id"
            );
        } catch (Throwable $e) {
            error_log("API v2 lazy migration failed for api_key_id=$api_key_id: " . $e->getMessage());
        }
        return $master_key;
    }

    return null;
}

function apiDecryptCredentialEntry($credential_ciphertext, $api_key_row_or_legacy_hash, #[\SensitiveParameter]$api_key_decrypt_password, $client_id = null)
{
    global $mysqli;

    // Backward-compatible signature: callers may pass either the api_keys row
    // (preferred) or just the legacy api_key_decrypt_hash string. Detect.
    if (is_array($api_key_row_or_legacy_hash)) {
        $site_encryption_master_key = apiUnlockMasterKey(
            $api_key_row_or_legacy_hash, $api_key_decrypt_password, $mysqli
        );
    } else {
        $site_encryption_master_key = decryptUserSpecificKey(
            $api_key_row_or_legacy_hash, $api_key_decrypt_password
        );
        if ($site_encryption_master_key === false || $site_encryption_master_key === '') {
            $site_encryption_master_key = null;
        }
    }

    if ($site_encryption_master_key === null) {
        return false;
    }

    // v3 path: per-client master key. The API path needs to fetch the
    // client_master_keys row directly (no session) and unwrap with the
    // shared master key just decrypted from the API key wrapping.
    if (isCredentialV3($credential_ciphertext)) {
        if (!$client_id) return false;
        $cid = intval($client_id);
        $cmk_row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT wrapped_under_shared FROM client_master_keys WHERE client_id = $cid LIMIT 1"));
        if (!$cmk_row) return false;
        try {
            $kek = expandMasterKeyToAes256($site_encryption_master_key);
            $client_master = cryptoDecryptV2(base64_decode($cmk_row['wrapped_under_shared'], true), $kek);
            sodium_memzero($kek);
            return decryptCredentialEntryV3($credential_ciphertext, $client_master);
        } catch (Throwable $e) {
            return false;
        }
    }

    // v2 path
    if (isCredentialV2($credential_ciphertext)) {
        try {
            return decryptCredentialEntryV2($credential_ciphertext, $site_encryption_master_key);
        } catch (Throwable $e) {
            return false;
        }
    }

    // Legacy v1
    $credential_iv         = substr($credential_ciphertext, 0, 16);
    $credential_ciphertext = substr($credential_ciphertext, 16);
    return openssl_decrypt(
        $credential_ciphertext, 'aes-128-cbc',
        $site_encryption_master_key, 0, $credential_iv
    );
}

function apiEncryptCredentialEntry(#[\SensitiveParameter]$credential_cleartext, $api_key_row_or_legacy_hash, #[\SensitiveParameter]$api_key_decrypt_password, $client_id = null)
{
    global $mysqli;

    if (is_array($api_key_row_or_legacy_hash)) {
        $site_encryption_master_key = apiUnlockMasterKey(
            $api_key_row_or_legacy_hash, $api_key_decrypt_password, $mysqli
        );
    } else {
        $site_encryption_master_key = decryptUserSpecificKey(
            $api_key_row_or_legacy_hash, $api_key_decrypt_password
        );
        if ($site_encryption_master_key === false || $site_encryption_master_key === '') {
            $site_encryption_master_key = null;
        }
    }

    if ($site_encryption_master_key === null) {
        return false;
    }

    // v3 path: when client_id is given, use the per-client key.
    if ($client_id && intval($client_id) > 0) {
        $cid = intval($client_id);
        // Look up or create the client master key. The API path can't use
        // ensureClientMasterKey() (it expects vaultMasterKeyFromSession).
        $cmk_row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT wrapped_under_shared FROM client_master_keys WHERE client_id = $cid LIMIT 1"));
        $kek = expandMasterKeyToAes256($site_encryption_master_key);
        try {
            if ($cmk_row) {
                $client_master = cryptoDecryptV2(base64_decode($cmk_row['wrapped_under_shared'], true), $kek);
            } else {
                // Lazy-create
                $client_master = random_bytes(16);
                $wrapped = cryptoEncryptV2($client_master, $kek);
                $wrapped_e = mysqli_real_escape_string($mysqli, base64_encode($wrapped));
                mysqli_query($mysqli, "INSERT INTO client_master_keys
                    SET client_id = $cid, wrapped_under_shared = '$wrapped_e',
                        key_version = 1, created_at = NOW()");
            }
            sodium_memzero($kek);
            return encryptCredentialEntryV3($credential_cleartext, $client_master);
        } catch (Throwable $e) {
            error_log('apiEncryptCredentialEntry v3 path failed: ' . $e->getMessage());
            // Fall through to v2 below
        }
    }

    return encryptCredentialEntryV2($credential_cleartext, $site_encryption_master_key);
}

// =====================================================================
// NIS2 fork: v2 crypto stack (AES-256-GCM + Argon2id)
//
// Format of a v2 ciphertext blob (raw binary):
//   +--------+--------+----------+------------+----------+
//   | ver(1) | alg(1) | iv(12)   | ciphertext | tag(16)  |
//   +--------+--------+----------+------------+----------+
// ver = 0x02, alg = 0x01 (AES-256-GCM)
//
// Wrapped master key (stored in users.user_specific_encryption_ciphertext_v2):
//   base64( salt(16) || v2_blob )
//   where v2_blob encrypts the master key under Argon2id(password, salt) → 32-byte KEK
//
// Credential entries written by this fork are stored as:
//   "v2:" || base64(v2_blob)
// The "v2:" prefix is unambiguous because legacy v1 entries start with a 16-char
// base64url IV (alphanumeric + -_), which never contains a colon.
// =====================================================================

const CRYPTO_VERSION_V2        = "\x02";
const CRYPTO_ALGO_AES256_GCM   = "\x01";
const CREDENTIAL_V2_PREFIX     = 'v2:';

function cryptoEncryptV2(#[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] string $key32): string
{
    if (strlen($key32) !== 32) {
        throw new RuntimeException('cryptoEncryptV2: key must be exactly 32 bytes');
    }
    $iv  = random_bytes(12);
    $tag = '';
    $ct  = openssl_encrypt(
        $plaintext, 'aes-256-gcm', $key32,
        OPENSSL_RAW_DATA, $iv, $tag, '', 16
    );
    if ($ct === false) {
        throw new RuntimeException('cryptoEncryptV2: openssl_encrypt failed');
    }
    return CRYPTO_VERSION_V2 . CRYPTO_ALGO_AES256_GCM . $iv . $ct . $tag;
}

function cryptoDecryptV2(string $blob, #[\SensitiveParameter] string $key32): string
{
    if (strlen($key32) !== 32) {
        throw new RuntimeException('cryptoDecryptV2: key must be exactly 32 bytes');
    }
    if (strlen($blob) < 2 + 12 + 16) {
        throw new RuntimeException('cryptoDecryptV2: blob too short');
    }
    if ($blob[0] !== CRYPTO_VERSION_V2 || $blob[1] !== CRYPTO_ALGO_AES256_GCM) {
        throw new RuntimeException('cryptoDecryptV2: unknown ciphertext version or algorithm');
    }
    $iv  = substr($blob, 2, 12);
    $tag = substr($blob, -16);
    $ct  = substr($blob, 14, -16);
    $pt  = openssl_decrypt(
        $ct, 'aes-256-gcm', $key32,
        OPENSSL_RAW_DATA, $iv, $tag
    );
    if ($pt === false) {
        throw new RuntimeException('cryptoDecryptV2: decryption or authentication failed');
    }
    return $pt;
}

function deriveKekArgon2id(#[\SensitiveParameter] string $secret, string $salt): string
{
    if (!function_exists('sodium_crypto_pwhash')) {
        throw new RuntimeException('deriveKekArgon2id: libsodium is required (sodium_crypto_pwhash missing)');
    }
    if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        throw new RuntimeException('deriveKekArgon2id: salt must be ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes');
    }
    return sodium_crypto_pwhash(
        32, $secret, $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );
}

function expandMasterKeyToAes256(#[\SensitiveParameter] string $master_key_raw): string
{
    return hash_hkdf('sha256', $master_key_raw, 32, 'itflow-nis2-aes256-v1');
}

function encryptUserSpecificKeyV2(#[\SensitiveParameter] string $master_key, #[\SensitiveParameter] string $password): string
{
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $kek  = deriveKekArgon2id($password, $salt);
    $blob = cryptoEncryptV2($master_key, $kek);
    sodium_memzero($kek);
    return base64_encode($salt . $blob);
}

function decryptUserSpecificKeyV2(string $stored, #[\SensitiveParameter] string $password): string
{
    $raw = base64_decode($stored, true);
    if ($raw === false || strlen($raw) < SODIUM_CRYPTO_PWHASH_SALTBYTES + 30) {
        throw new RuntimeException('decryptUserSpecificKeyV2: invalid stored value');
    }
    $salt = substr($raw, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $blob = substr($raw, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $kek  = deriveKekArgon2id($password, $salt);
    try {
        return cryptoDecryptV2($blob, $kek);
    } finally {
        sodium_memzero($kek);
    }
}

function unlockUserMasterKey(array $user_row, #[\SensitiveParameter] string $password, mysqli $mysqli): ?string
{
    $user_id = intval($user_row['user_id'] ?? 0);

    // Prefer v2 if present; fail closed if v2 fails (don't silently regress to v1).
    if (!empty($user_row['user_specific_encryption_ciphertext_v2'])) {
        try {
            return decryptUserSpecificKeyV2(
                $user_row['user_specific_encryption_ciphertext_v2'],
                $password
            );
        } catch (Throwable $e) {
            error_log("unlockUserMasterKey: v2 unwrap failed for user_id=$user_id: " . $e->getMessage());
            return null;
        }
    }

    // No v2 yet: decrypt v1 and lazy-migrate.
    if (!empty($user_row['user_specific_encryption_ciphertext'])) {
        $master_key = decryptUserSpecificKey(
            $user_row['user_specific_encryption_ciphertext'],
            $password
        );
        if ($master_key === false || $master_key === '' || strlen($master_key) !== 16) {
            // decryptUserSpecificKey already logs the specific failure mode.
            error_log("unlockUserMasterKey: v1 unwrap returned no usable master key for user_id=$user_id. The vault will stay locked. If password is correct, the v1 column is corrupt — recover with: php scripts/reset_master_key.php $user_id <password>");
            return null;
        }
        try {
            $v2 = encryptUserSpecificKeyV2($master_key, $password);
            $v2_escaped = mysqli_real_escape_string($mysqli, $v2);
            mysqli_query(
                $mysqli,
                "UPDATE users
                 SET user_specific_encryption_ciphertext_v2 = '$v2_escaped'
                 WHERE user_id = $user_id"
            );
        } catch (Throwable $e) {
            error_log("v2 lazy migration failed for user $user_id: " . $e->getMessage());
        }
        return $master_key;
    }

    error_log("unlockUserMasterKey: user_id=$user_id has no wrapped master key (neither v1 nor v2)");
    return null;
}

function isCredentialV2(string $stored): bool
{
    return strncmp($stored, CREDENTIAL_V2_PREFIX, strlen(CREDENTIAL_V2_PREFIX)) === 0;
}

function decryptCredentialEntryV2(string $stored, #[\SensitiveParameter] string $master_key_raw): string
{
    if (!isCredentialV2($stored)) {
        throw new RuntimeException('decryptCredentialEntryV2: not a v2 credential');
    }
    $b64  = substr($stored, strlen(CREDENTIAL_V2_PREFIX));
    $blob = base64_decode($b64, true);
    if ($blob === false) {
        throw new RuntimeException('decryptCredentialEntryV2: invalid base64');
    }
    $key32 = expandMasterKeyToAes256($master_key_raw);
    try {
        return cryptoDecryptV2($blob, $key32);
    } finally {
        sodium_memzero($key32);
    }
}

// =====================================================================
// NIS2 fork phase 10: per-user X25519 keypairs + per-user client grants
//
// Each user owns a Curve25519 (X25519) keypair. Their public key is
// readable by anyone (it lives in users.user_pubkey). Their private key
// is wrapped under their unlock factor (Argon2id KEK from password) and
// only they can unwrap it.
//
// Client master keys are stored once per client (existing client_master_keys
// table from phase 9). Authorised users get a per-user grant: the client
// master key sealed-box-encrypted to their public key, stored in
// user_client_grants.
//
// Compromise model: a malicious / phished agent X can decrypt only the
// client master keys for which a grant exists in user_client_grants
// for X. Other clients' grants are sealed under other users' public
// keys; X cannot open them with their private key.
//
// Migration is lazy. At first login post-migration:
//   - generate keypair if missing
//   - backfill grants for clients X has app-layer access to
// During migration the legacy shared-master-key path (client_master_keys
// .wrapped_under_shared) remains usable as a fallback so users without
// grants yet can still read credentials.
// =====================================================================

if (!function_exists('userGenerateKeypairForPassword')) {

    /**
     * Generate a new X25519 keypair for a user, with the private key
     * wrapped under an Argon2id KEK derived from $password.
     *
     * Returns ['pubkey_b64' => ..., 'wrapped_privkey_b64' => ...].
     */
    function userGenerateKeypairForPassword(#[\SensitiveParameter] string $password): array
    {
        $privkey = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);   // 32 bytes
        $pubkey  = sodium_crypto_box_publickey_from_secretkey($privkey);

        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $kek  = deriveKekArgon2id($password, $salt);
        $wrap = cryptoEncryptV2($privkey, $kek);
        sodium_memzero($kek);
        sodium_memzero($privkey);

        return [
            'pubkey_b64'         => base64_encode($pubkey),
            'wrapped_privkey_b64'=> base64_encode($salt . $wrap),
        ];
    }

    /**
     * Unwrap a stored wrapped privkey using a password. Returns the raw
     * 32-byte X25519 secret key on success, or null on auth/format
     * failure.
     */
    function userUnwrapPrivkey(string $wrapped_b64, #[\SensitiveParameter] string $password): ?string
    {
        $raw = base64_decode($wrapped_b64, true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_PWHASH_SALTBYTES + 30) {
            return null;
        }
        $salt = substr($raw, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $blob = substr($raw, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        try {
            $kek = deriveKekArgon2id($password, $salt);
            $privkey = cryptoDecryptV2($blob, $kek);
            sodium_memzero($kek);
            return $privkey;
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * Re-wrap a privkey under a new password. Used at password change
     * so the user's keypair survives the rotation.
     */
    function userRewrapPrivkey(string $current_wrapped_b64, #[\SensitiveParameter] string $current_password, #[\SensitiveParameter] string $new_password): ?string
    {
        $privkey = userUnwrapPrivkey($current_wrapped_b64, $current_password);
        if ($privkey === null) return null;

        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $kek  = deriveKekArgon2id($new_password, $salt);
        try {
            $wrap = cryptoEncryptV2($privkey, $kek);
            return base64_encode($salt . $wrap);
        } finally {
            sodium_memzero($kek);
            sodium_memzero($privkey);
        }
    }

    /**
     * Wrap a client master key for a recipient using their X25519 public
     * key. Anyone holding $recipient_pubkey can do this; only the holder
     * of the matching private key can unwrap.
     */
    function wrapClientKeyForUser(#[\SensitiveParameter] string $client_master, string $recipient_pubkey_b64): string
    {
        $pub = base64_decode($recipient_pubkey_b64, true);
        if ($pub === false || strlen($pub) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new RuntimeException('wrapClientKeyForUser: invalid recipient pubkey');
        }
        $sealed = sodium_crypto_box_seal($client_master, $pub);
        return base64_encode($sealed);
    }

    /**
     * Unwrap a client master key from a sealed box using the user's privkey.
     * Returns null on bad ciphertext / wrong key.
     */
    function unwrapClientKeyFromGrant(string $wrapped_b64, #[\SensitiveParameter] string $privkey): ?string
    {
        $sealed = base64_decode($wrapped_b64, true);
        if ($sealed === false) return null;
        if (strlen($privkey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) return null;

        $pub = sodium_crypto_box_publickey_from_secretkey($privkey);
        $kp  = sodium_crypto_box_keypair_from_secretkey_and_publickey($privkey, $pub);
        try {
            $opened = sodium_crypto_box_seal_open($sealed, $kp);
            return $opened === false ? null : $opened;
        } finally {
            sodium_memzero($kp);
        }
    }

    /**
     * Push the user's privkey into the session, wrapped under the same
     * session_key cookie that already wraps the master_key. Mirrors
     * generateUserSessionKey but for the privkey side channel.
     */
    function pushUserPrivkeyToSession(#[\SensitiveParameter] string $privkey_raw): void
    {
        if (empty($_COOKIE['user_encryption_session_key'])) {
            // generateUserSessionKey() must have been called already.
            return;
        }
        $session_key = $_COOKIE['user_encryption_session_key'];
        $iv = randomString();
        $ct = openssl_encrypt($privkey_raw, 'aes-128-cbc', $session_key, 0, $iv);
        if ($ct === false) return;
        $_SESSION['user_privkey_session_ciphertext'] = $ct;
        $_SESSION['user_privkey_session_iv']         = $iv;
    }

    /**
     * Read the user's privkey out of the session if available.
     */
    function userPrivkeyFromSession(): ?string
    {
        if (empty($_SESSION['user_privkey_session_ciphertext'])
            || empty($_SESSION['user_privkey_session_iv'])
            || empty($_COOKIE['user_encryption_session_key'])) {
            return null;
        }
        $pt = openssl_decrypt(
            $_SESSION['user_privkey_session_ciphertext'],
            'aes-128-cbc',
            $_COOKIE['user_encryption_session_key'],
            0,
            $_SESSION['user_privkey_session_iv']
        );
        return ($pt === false || $pt === '') ? null : $pt;
    }

    /**
     * Lazy-backfill: ensure $user_id has a keypair (generating one from
     * $password if missing), then ensure they have user_client_grants
     * rows for every client_master_key they have application-layer access
     * to. Requires the just-unwrapped shared master key to lookup client
     * master keys from the legacy wrapping during the transition.
     *
     * Returns the unwrapped privkey on success, null on failure.
     */
    function backfillUserCryptoMaterial(int $user_id, #[\SensitiveParameter] string $password, #[\SensitiveParameter] ?string $shared_master_key, mysqli $mysqli): ?string
    {
        $row = mysqli_fetch_assoc(mysqli_query(
            $mysqli,
            "SELECT user_pubkey, user_privkey_wrapped FROM users WHERE user_id = $user_id LIMIT 1"
        ));
        if (!$row) return null;

        if (empty($row['user_pubkey']) || empty($row['user_privkey_wrapped'])) {
            $kp = userGenerateKeypairForPassword($password);
            $pub_e  = mysqli_real_escape_string($mysqli, $kp['pubkey_b64']);
            $priv_e = mysqli_real_escape_string($mysqli, $kp['wrapped_privkey_b64']);
            mysqli_query($mysqli,
                "UPDATE users SET user_pubkey = '$pub_e', user_privkey_wrapped = '$priv_e' WHERE user_id = $user_id");
            $row['user_pubkey']           = $kp['pubkey_b64'];
            $row['user_privkey_wrapped']  = $kp['wrapped_privkey_b64'];
        }

        $privkey = userUnwrapPrivkey($row['user_privkey_wrapped'], $password);
        if ($privkey === null) {
            error_log("backfillUserCryptoMaterial: privkey unwrap failed for user_id=$user_id");
            return null;
        }

        $pubkey_b64 = $row['user_pubkey'];

        // Backfill grants for every client this user has access to. We use
        // the same access query the rest of the app uses: if there are
        // explicit user_client_permissions rows, those are the allowed
        // clients; otherwise (admin or unrestricted), all non-archived
        // clients are allowed.
        $perm_rs = mysqli_query($mysqli,
            "SELECT client_id FROM user_client_permissions WHERE user_id = $user_id");
        $allowed_ids = [];
        if ($perm_rs) {
            while ($r = mysqli_fetch_assoc($perm_rs)) {
                $allowed_ids[] = intval($r['client_id']);
            }
        }
        if (empty($allowed_ids)) {
            $rs = mysqli_query($mysqli,
                "SELECT client_id FROM clients WHERE client_archived_at IS NULL");
            if ($rs) {
                while ($r = mysqli_fetch_assoc($rs)) $allowed_ids[] = intval($r['client_id']);
            }
        }

        if (!empty($allowed_ids) && $shared_master_key !== null) {
            $kek = expandMasterKeyToAes256($shared_master_key);
            try {
                foreach ($allowed_ids as $cid) {
                    $exists = mysqli_fetch_assoc(mysqli_query($mysqli,
                        "SELECT 1 FROM user_client_grants WHERE user_id = $user_id AND client_id = $cid LIMIT 1"));
                    if ($exists) continue;

                    $cmk_row = mysqli_fetch_assoc(mysqli_query($mysqli,
                        "SELECT wrapped_under_shared FROM client_master_keys WHERE client_id = $cid LIMIT 1"));
                    if (!$cmk_row) continue;

                    $cmk_blob = base64_decode($cmk_row['wrapped_under_shared'], true);
                    if ($cmk_blob === false) continue;

                    try {
                        $client_master = cryptoDecryptV2($cmk_blob, $kek);
                        $wrapped       = wrapClientKeyForUser($client_master, $pubkey_b64);
                        sodium_memzero($client_master);
                        $wrapped_e     = mysqli_real_escape_string($mysqli, $wrapped);
                        mysqli_query($mysqli, "
                            INSERT IGNORE INTO user_client_grants
                            SET user_id = $user_id, client_id = $cid,
                                wrapped_client_key = '$wrapped_e',
                                granted_at = NOW(),
                                granted_by_user_id = NULL
                        ");
                    } catch (Throwable $e) {
                        error_log("grant backfill failed for user $user_id client $cid: " . $e->getMessage());
                    }
                }
            } finally {
                sodium_memzero($kek);
            }
        }

        return $privkey;
    }

    /**
     * After we obtain a client master key via the shared-master fallback,
     * write a per-user grant for the CURRENT user if we don't have one yet.
     * Best-effort; failures are logged but never block the calling write.
     */
    function materialiseGrantForCurrentUser(int $client_id, #[\SensitiveParameter] string $client_master, mysqli $mysqli): void
    {
        if (empty($_SESSION['user_id'])) return;
        $user_id = intval($_SESSION['user_id']);

        $row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT user_pubkey FROM users WHERE user_id = $user_id LIMIT 1"));
        if (!$row || empty($row['user_pubkey'])) return;

        $exists = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT 1 FROM user_client_grants WHERE user_id = $user_id AND client_id = $client_id LIMIT 1"));
        if ($exists) return;

        try {
            $wrapped = wrapClientKeyForUser($client_master, $row['user_pubkey']);
            $wrapped_e = mysqli_real_escape_string($mysqli, $wrapped);
            mysqli_query($mysqli, "
                INSERT IGNORE INTO user_client_grants
                SET user_id = $user_id, client_id = $client_id,
                    wrapped_client_key = '$wrapped_e',
                    granted_at = NOW(),
                    granted_by_user_id = NULL
            ");
        } catch (Throwable $e) {
            error_log("materialiseGrantForCurrentUser: $user_id/$client_id: " . $e->getMessage());
        }
    }

    /**
     * Admin operation: grant another user access to a client. The admin
     * must already have a usable client_master_key in hand (either via
     * their own grant or via the shared-master fallback).
     *
     * If $target_user_id has no public key yet (i.e. has not logged in
     * since the phase-10 migration), the grant cannot be materialised
     * yet. The function returns false and the lazy backfill at the
     * target's next login will create it.
     */
    function adminGrantClientToUser(int $admin_user_id, int $target_user_id, int $client_id, mysqli $mysqli): bool
    {
        $admin_user_id  = intval($admin_user_id);
        $target_user_id = intval($target_user_id);
        $client_id      = intval($client_id);
        if ($admin_user_id <= 0 || $target_user_id <= 0 || $client_id <= 0) {
            return false;
        }

        $tgt = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT user_pubkey FROM users WHERE user_id = $target_user_id LIMIT 1"));
        if (!$tgt || empty($tgt['user_pubkey'])) {
            return false;  // target hasn't logged in since the migration
        }

        $client_master = getClientMasterKeyViaGrant($client_id, $mysqli)
                      ?? ensureClientMasterKey($client_id, $mysqli);
        if ($client_master === null) {
            return false;
        }

        try {
            $wrapped = wrapClientKeyForUser($client_master, $tgt['user_pubkey']);
            sodium_memzero($client_master);
            $wrapped_e = mysqli_real_escape_string($mysqli, $wrapped);
            mysqli_query($mysqli, "
                INSERT INTO user_client_grants
                SET user_id = $target_user_id, client_id = $client_id,
                    wrapped_client_key = '$wrapped_e',
                    granted_at = NOW(),
                    granted_by_user_id = $admin_user_id
                ON DUPLICATE KEY UPDATE
                    wrapped_client_key = VALUES(wrapped_client_key),
                    granted_at = VALUES(granted_at),
                    granted_by_user_id = VALUES(granted_by_user_id)
            ");
            return true;
        } catch (Throwable $e) {
            error_log("adminGrantClientToUser failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Revoke a user's grant for a client. Used when an admin removes
     * application-layer access. Wrapping is destroyed; user can no longer
     * decrypt that client via the compartmentalised path.
     */
    function adminRevokeClientGrant(int $target_user_id, int $client_id, mysqli $mysqli): bool
    {
        $target_user_id = intval($target_user_id);
        $client_id      = intval($client_id);
        if ($target_user_id <= 0 || $client_id <= 0) return false;
        mysqli_query($mysqli,
            "DELETE FROM user_client_grants
             WHERE user_id = $target_user_id AND client_id = $client_id");
        return mysqli_affected_rows($mysqli) > 0;
    }

    /**
     * Look up the client master key for a given client_id using the
     * current user's grant. Returns null if the user has no grant
     * (which should fall back to the shared-master path during migration).
     */
    function getClientMasterKeyViaGrant(int $client_id, mysqli $mysqli): ?string
    {
        if (empty($_SESSION['user_id'])) return null;
        $user_id = intval($_SESSION['user_id']);

        $privkey = userPrivkeyFromSession();
        if ($privkey === null) return null;

        $client_id = intval($client_id);
        $row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT wrapped_client_key FROM user_client_grants
             WHERE user_id = $user_id AND client_id = $client_id LIMIT 1"));
        if (!$row) return null;

        $cmk = unwrapClientKeyFromGrant($row['wrapped_client_key'], $privkey);
        sodium_memzero($privkey);

        if ($cmk !== null) {
            // best-effort last_used_at update; fire-and-forget
            mysqli_query($mysqli,
                "UPDATE user_client_grants SET last_used_at = NOW()
                 WHERE user_id = $user_id AND client_id = $client_id");
        }
        return $cmk;
    }
}

// =====================================================================
// NIS2 fork phase 9: per-client master keys (v3 credential format)
//
// Format of a v3 stored credential:
//   "v3:" || base64( cryptoEncryptV2(plaintext, HKDF(client_master_key)) )
//
// The client_master_key is a 16-byte random secret stored in
// client_master_keys, wrapped under the shared session master key. Each
// client has its own key, enabling per-client rotation and secure delete.
// =====================================================================

const CREDENTIAL_V3_PREFIX = 'v3:';

function isCredentialV3(string $stored): bool
{
    return strncmp($stored, CREDENTIAL_V3_PREFIX, strlen(CREDENTIAL_V3_PREFIX)) === 0;
}

/**
 * Read or lazily create a client's master key.
 *
 * Requires the session master key (vault unlocked). Returns the raw
 * 16-byte client master key, or null if the vault is locked or the
 * stored row is malformed.
 */
function ensureClientMasterKey(int $client_id, mysqli $mysqli): ?string
{
    $client_id = intval($client_id);
    if ($client_id <= 0) return null;

    $session_master = vaultMasterKeyFromSession();
    if ($session_master === null) {
        return null;
    }
    $kek = expandMasterKeyToAes256($session_master);

    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT wrapped_under_shared FROM client_master_keys
         WHERE client_id = $client_id LIMIT 1"
    ));

    if ($row) {
        try {
            $wrapped = base64_decode($row['wrapped_under_shared'], true);
            if ($wrapped === false) {
                error_log("ensureClientMasterKey: malformed wrapping for client_id=$client_id");
                return null;
            }
            $client_master = cryptoDecryptV2($wrapped, $kek);
            sodium_memzero($kek);
            return $client_master;
        } catch (Throwable $e) {
            error_log("ensureClientMasterKey: unwrap failed for client_id=$client_id: " . $e->getMessage());
            return null;
        }
    }

    // Lazy-create. Generate a fresh 16-byte client master key, wrap it under
    // the session master key, store, and return.
    $client_master = random_bytes(16);
    try {
        $wrapped = cryptoEncryptV2($client_master, $kek);
    } catch (Throwable $e) {
        error_log("ensureClientMasterKey: wrap failed for client_id=$client_id: " . $e->getMessage());
        return null;
    } finally {
        sodium_memzero($kek);
    }
    $wrapped_b64 = base64_encode($wrapped);
    $wrapped_e   = mysqli_real_escape_string($mysqli, $wrapped_b64);

    mysqli_query(
        $mysqli,
        "INSERT INTO client_master_keys
         SET client_id = $client_id,
             wrapped_under_shared = '$wrapped_e',
             key_version = 1,
             created_at = NOW()"
    );

    return $client_master;
}

function encryptCredentialEntryV3(#[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] string $client_master): string
{
    $key32 = expandMasterKeyToAes256($client_master);
    try {
        $blob = cryptoEncryptV2($plaintext, $key32);
        return CREDENTIAL_V3_PREFIX . base64_encode($blob);
    } finally {
        sodium_memzero($key32);
    }
}

function decryptCredentialEntryV3(string $stored, #[\SensitiveParameter] string $client_master): string
{
    if (!isCredentialV3($stored)) {
        throw new RuntimeException('decryptCredentialEntryV3: not a v3 credential');
    }
    $b64  = substr($stored, strlen(CREDENTIAL_V3_PREFIX));
    $blob = base64_decode($b64, true);
    if ($blob === false) {
        throw new RuntimeException('decryptCredentialEntryV3: invalid base64');
    }
    $key32 = expandMasterKeyToAes256($client_master);
    try {
        return cryptoDecryptV2($blob, $key32);
    } finally {
        sodium_memzero($key32);
    }
}

function encryptCredentialEntryV2(#[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] string $master_key_raw): string
{
    $key32 = expandMasterKeyToAes256($master_key_raw);
    try {
        $blob = cryptoEncryptV2($plaintext, $key32);
        return CREDENTIAL_V2_PREFIX . base64_encode($blob);
    } finally {
        sodium_memzero($key32);
    }
}

// Get domain general info (whois + NS/A/MX records)
function getDomainRecords($name)
{
    $records = array();

    // Only run if we think the domain is valid
    if (!filter_var($name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || !checkdnsrr($name, 'SOA')) {
        $records['a'] = '';
        $records['ns'] = '';
        $records['mx'] = '';
        $records['whois'] = '';
        return $records;
    }

    $domain = escapeshellarg(str_replace('www.', '', $name));

    // Get A, NS, MX, TXT, and WHOIS records
    $records['a'] = trim(strip_tags(shell_exec("dig +short $domain")));
    $records['ns'] = trim(strip_tags(shell_exec("dig +short NS $domain")));
    $records['mx'] = trim(strip_tags(shell_exec("dig +short MX $domain")));
    $records['txt'] = trim(strip_tags(shell_exec("dig +short TXT $domain")));
    $records['whois'] = substr(trim(strip_tags(shell_exec("whois -H $domain | head -30 | sed 's/   //g'"))), 0, 254);

    // Sort A records (if multiple records exist)
    if (!empty($records['a'])) {
        $a_records = explode("\n", $records['a']);
        array_walk($a_records, function(&$record) {
            $record = trim($record);
        });
        sort($a_records);
        $records['a'] = implode("\n", $a_records);
    }

    // Sort NS records (if multiple records exist)
    if (!empty($records['ns'])) {
        $ns_records = explode("\n", $records['ns']);
        array_walk($ns_records, function(&$record) {
            $record = trim($record);
        });
        sort($ns_records);
        $records['ns'] = implode("\n", $ns_records);
    }

    // Sort MX records (if multiple records exist)
    if (!empty($records['mx'])) {
        $mx_records = explode("\n", $records['mx']);
        array_walk($mx_records, function(&$record) {
            $record = trim($record);
        });
        sort($mx_records);
        $records['mx'] = implode("\n", $mx_records);
    }

    // Sort TXT records (if multiple records exist)
    if (!empty($records['txt'])) {
        $txt_records = explode("\n", $records['txt']);
        array_walk($txt_records, function(&$record) {
            $record = trim($record);
        });
        sort($txt_records);
        $records['txt'] = implode("\n", $txt_records);
    }

    return $records;
}

// Used to automatically attempt to get SSL certificates as part of adding domains
// The logic for the fetch (sync) button on the client_certificates page is in ajax.php, and allows ports other than 443
function getSSL($full_name)
{

    // Parse host and port
    $name = parse_url("//$full_name", PHP_URL_HOST);
    $port = parse_url("//$full_name", PHP_URL_PORT);

    // Default port
    if (!$port) {
        $port = "443";
    }

    $certificate = array();
    $certificate['success'] = false;

    // Only run if we think the domain is valid
    if (!filter_var($name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        $certificate['expire'] = '';
        $certificate['issued_by'] = '';
        $certificate['public_key'] = '';
        return $certificate;
    }

    // Get SSL/TSL certificate (using verify peer false to allow for self-signed certs) for domain on default port
    $socket = "ssl://$name:$port";
    $get = stream_context_create(array("ssl" => array("capture_peer_cert" => true, "verify_peer" => false,)));
    $read = stream_socket_client($socket, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $get);

    // If the socket connected
    if ($read) {
        $cert = stream_context_get_params($read);
        $cert_public_key_obj = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
        openssl_x509_export($cert['options']['ssl']['peer_certificate'], $export);

        if ($cert_public_key_obj) {
            $certificate['success'] = true;
            $certificate['expire'] = date('Y-m-d', $cert_public_key_obj['validTo_time_t']);
            $certificate['issued_by'] = strip_tags($cert_public_key_obj['issuer']['O']);
            $certificate['public_key'] = $export;
        }
    }

    return $certificate;
}

function strtoAZaz09($string)
{
    // Gets rid of non-alphanumerics
    return preg_replace('/[^A-Za-z0-9_-]/', '', $string);
}

// Cross-Site Request Forgery check for sensitive functions
// Validates the CSRF token provided matches the one in the users session
function validateCSRFToken($token)
{
    if (hash_equals($token, $_SESSION['csrf_token'])) {
        return true;
    } else {
        $_SESSION['alert_type'] = "warning";
        $_SESSION['alert_message'] = "CSRF token verification failed. Try again, or log out to refresh your token.";
        header("Location: index.php");
        exit();
    }
}

/*
 * LEGACY Role validation
 * Admin - 3
 * Tech - 2
 * Accountant - 1
 */

function validateAdminRole() {
    global $session_user_role;
    if (!isset($session_user_role) || $session_user_role != 3) {
        $_SESSION['alert_type'] = "danger";
        $_SESSION['alert_message'] = WORDING_ROLECHECK_FAILED;
        header("Location: " . $_SERVER["HTTP_REFERER"]);
        exit();
    }
}

// LEGACY
// Validates a user is a tech (or admin). Stops page load and attempts to direct away from the page if not (i.e. user is an accountant)
function validateTechRole() {
    global $session_user_role;
    if (!isset($session_user_role) || $session_user_role == 1) {
        $_SESSION['alert_type'] = "danger";
        $_SESSION['alert_message'] = WORDING_ROLECHECK_FAILED;
        header("Location: " . $_SERVER["HTTP_REFERER"]);
        exit();
    }
}

// LEGACY
// Validates a user is an accountant (or admin). Stops page load and attempts to direct away from the page if not (i.e. user is a tech)
function validateAccountantRole() {
    global $session_user_role;
    if (!isset($session_user_role) || $session_user_role == 2) {
        $_SESSION['alert_type'] = "danger";
        $_SESSION['alert_message'] = WORDING_ROLECHECK_FAILED;
        header("Location: " . $_SERVER["HTTP_REFERER"]);
        exit();
    }
}

function roundUpToNearestMultiple($n, $increment = 1000)
{
    return (int) ($increment * ceil($n / $increment));
}

function getAssetIcon($asset_type)
{
    if ($asset_type == 'Laptop') {
        $device_icon = "laptop";
    } elseif ($asset_type == 'Desktop') {
        $device_icon = "desktop";
    } elseif ($asset_type == 'Server') {
        $device_icon = "server";
    } elseif ($asset_type == 'Printer') {
        $device_icon = "print";
    } elseif ($asset_type == 'Camera') {
        $device_icon = "video";
    } elseif ($asset_type == 'Switch') {
        $device_icon = "network-wired";
    } elseif ($asset_type == 'Firewall/Router') {
        $device_icon = "fire-alt";
    } elseif ($asset_type == 'Access Point') {
        $device_icon = "wifi";
    } elseif ($asset_type == 'Phone') {
        $device_icon = "phone";
    } elseif ($asset_type == 'Mobile Phone') {
        $device_icon = "mobile-alt";
    } elseif ($asset_type == 'Tablet') {
        $device_icon = "tablet-alt";
    } elseif ($asset_type == 'Display') {
        $device_icon = "tv";
    } elseif ($asset_type == 'Virtual Machine') {
        $device_icon = "cloud";
    } else {
        $device_icon = "tag";
    }

    return $device_icon;
}

function getInvoiceBadgeColor($invoice_status)
{
    if ($invoice_status == "Sent") {
        $invoice_badge_color = "warning text-white";
    } elseif ($invoice_status == "Viewed") {
        $invoice_badge_color = "info";
    } elseif ($invoice_status == "Partial") {
        $invoice_badge_color = "primary";
    } elseif ($invoice_status == "Paid") {
        $invoice_badge_color = "success";
    } elseif ($invoice_status == "Cancelled") {
        $invoice_badge_color = "danger";
    } else {
        $invoice_badge_color = "secondary";
    }

    return $invoice_badge_color;
}

// Pass $_FILE['file'] to check an uploaded file before saving it
function checkFileUpload($file, $allowed_extensions)
{
    // Variables
    $name = $file['name'];
    $tmp = $file['tmp_name'];
    $size = $file['size'];

    $extarr = explode('.', $name);
    $extension = strtolower(end($extarr));

    // Check a file is actually attached/uploaded
    if ($tmp === '') {
        // No file uploaded
        return false;
    }

    // Check the extension is allowed
    if (!in_array($extension, $allowed_extensions)) {
        // Extension not allowed
        return false;
    }

    // Check the size is under 500 MB
    $maxSizeBytes = 500 * 1024 * 1024; // 500 MB
    if ($size > $maxSizeBytes) {
        return "File size exceeds the limit.";
    }

    // Read the file content
    $fileContent = file_get_contents($tmp);

    // Hash the file content using SHA-256
    $hashedContent = hash('md5', $fileContent);

    // Generate a secure filename using the hashed content
    $secureFilename = $hashedContent . randomString(2) . '.' . $extension;

    return $secureFilename;
}

function sanitizeInput($input) {
    global $mysqli;

    if (!empty($input)) {
        // Only convert encoding if it's NOT valid UTF-8
        if (!mb_check_encoding($input, 'UTF-8')) {
            // Try converting from Windows-1252 as a safe default fallback
            $input = mb_convert_encoding($input, 'UTF-8', 'Windows-1252');
        }
    }

    // Remove HTML and PHP tags
    $input = strip_tags((string) $input);

    // Trim white space
    $input = trim($input);

    // Escape for SQL
    $input = mysqli_real_escape_string($mysqli, $input);

    return $input;
}

function cleanInput($input) {
    // Only process non-empty input
    if (!empty($input)) {
        // Normalize encoding to UTF-8 if it’s not valid
        if (!mb_check_encoding($input, 'UTF-8')) {
            // Convert from Windows-1252 as a safe fallback
            $input = mb_convert_encoding($input, 'UTF-8', 'Windows-1252');
        }
    }

    // Remove HTML and PHP tags
    $input = strip_tags((string) $input);

    // Trim whitespace
    $input = trim($input);

    return $input;
}


function sanitizeForEmail($data)
{
    $sanitized = htmlspecialchars($data);
    $sanitized = strip_tags($sanitized);
    $sanitized = trim($sanitized);
    return $sanitized;
}

function timeAgo($datetime)
{
    if (is_null($datetime)) {
        return "-";
    }

    $time = strtotime($datetime);
    $difference = $time - time(); // Changed to handle future dates

    if ($difference == 0) {
        return 'right now';
    }

    $isFuture = $difference > 0; // Check if the date is in the future
    $difference = abs($difference); // Absolute value for calculation

    $timeRules = array(
        31536000 => 'year',
        2592000 => 'month',
        604800 => 'week',
        86400 => 'day',
        3600 => 'hour',
        60 => 'minute',
        1 => 'second'
    );

    foreach ($timeRules as $secs => $str) {
        $div = $difference / $secs;
        if ($div >= 1) {
            $t = round($div);
            $timeStr = $t . ' ' . $str . ($t > 1 ? 's' : '');
            return $isFuture ? 'in ' . $timeStr : $timeStr . ' ago';
        }
    }
}

// Function to remove Emojis in messages, this seems to break the mail queue
function removeEmoji($text)
{
    return preg_replace('/\x{1F3F4}\x{E0067}\x{E0062}(?:\x{E0077}\x{E006C}\x{E0073}|\x{E0073}\x{E0063}\x{E0074}|\x{E0065}\x{E006E}\x{E0067})\x{E007F}|(?:\x{1F9D1}\x{1F3FF}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F9D1}|\x{1F469}\x{1F3FF}\x{200D}\x{1F91D}\x{200D}[\x{1F468}\x{1F469}]|\x{1FAF1}\x{1F3FF}\x{200D}\x{1FAF2})[\x{1F3FB}-\x{1F3FE}]|(?:\x{1F9D1}\x{1F3FE}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F9D1}|\x{1F469}\x{1F3FE}\x{200D}\x{1F91D}\x{200D}[\x{1F468}\x{1F469}]|\x{1FAF1}\x{1F3FE}\x{200D}\x{1FAF2})[\x{1F3FB}-\x{1F3FD}\x{1F3FF}]|(?:\x{1F9D1}\x{1F3FD}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F9D1}|\x{1F469}\x{1F3FD}\x{200D}\x{1F91D}\x{200D}[\x{1F468}\x{1F469}]|\x{1FAF1}\x{1F3FD}\x{200D}\x{1FAF2})[\x{1F3FB}\x{1F3FC}\x{1F3FE}\x{1F3FF}]|(?:\x{1F9D1}\x{1F3FC}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F9D1}|\x{1F469}\x{1F3FC}\x{200D}\x{1F91D}\x{200D}[\x{1F468}\x{1F469}]|\x{1FAF1}\x{1F3FC}\x{200D}\x{1FAF2})[\x{1F3FB}\x{1F3FD}-\x{1F3FF}]|(?:\x{1F9D1}\x{1F3FB}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F9D1}|\x{1F469}\x{1F3FB}\x{200D}\x{1F91D}\x{200D}[\x{1F468}\x{1F469}]|\x{1FAF1}\x{1F3FB}\x{200D}\x{1FAF2})[\x{1F3FC}-\x{1F3FF}]|\x{1F468}(?:\x{1F3FB}(?:\x{200D}(?:\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FF}]|\x{1F468}[\x{1F3FB}-\x{1F3FF}])|\x{200D}(?:\x{1F48B}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FF}]|\x{1F468}[\x{1F3FB}-\x{1F3FF}]))|\x{1F91D}\x{200D}\x{1F468}[\x{1F3FC}-\x{1F3FF}]|[\x{2695}\x{2696}\x{2708}]\x{FE0F}|[\x{2695}\x{2696}\x{2708}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]))?|[\x{1F3FC}-\x{1F3FF}]\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FF}]|\x{1F468}[\x{1F3FB}-\x{1F3FF}])|\x{200D}(?:\x{1F48B}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FF}]|\x{1F468}[\x{1F3FB}-\x{1F3FF}]))|\x{200D}(?:\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D})?|\x{200D}(?:\x{1F48B}\x{200D})?)\x{1F468}|[\x{1F468}\x{1F469}]\x{200D}(?:\x{1F466}\x{200D}\x{1F466}|\x{1F467}\x{200D}[\x{1F466}\x{1F467}])|\x{1F466}\x{200D}\x{1F466}|\x{1F467}\x{200D}[\x{1F466}\x{1F467}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FF}\x{200D}(?:\x{1F91D}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FE}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FE}\x{200D}(?:\x{1F91D}\x{200D}\x{1F468}[\x{1F3FB}-\x{1F3FD}\x{1F3FF}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FD}\x{200D}(?:\x{1F91D}\x{200D}\x{1F468}[\x{1F3FB}\x{1F3FC}\x{1F3FE}\x{1F3FF}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FC}\x{200D}(?:\x{1F91D}\x{200D}\x{1F468}[\x{1F3FB}\x{1F3FD}-\x{1F3FF}]|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|(?:\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{200D}[\x{2695}\x{2696}\x{2708}])\x{FE0F}|\x{200D}(?:[\x{1F468}\x{1F469}]\x{200D}[\x{1F466}\x{1F467}]|[\x{1F466}\x{1F467}])|\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FF}|\x{1F3FE}|\x{1F3FD}|\x{1F3FC}|\x{200D}[\x{2695}\x{2696}\x{2708}])?|(?:\x{1F469}(?:\x{1F3FB}\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}])|\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}]))|[\x{1F3FC}-\x{1F3FF}]\x{200D}\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}])|\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}])))|\x{1F9D1}[\x{1F3FB}-\x{1F3FF}]\x{200D}\x{1F91D}\x{200D}\x{1F9D1})[\x{1F3FB}-\x{1F3FF}]|\x{1F469}\x{200D}\x{1F469}\x{200D}(?:\x{1F466}\x{200D}\x{1F466}|\x{1F467}\x{200D}[\x{1F466}\x{1F467}])|\x{1F469}(?:\x{200D}(?:\x{2764}(?:\x{FE0F}\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}])|\x{200D}(?:\x{1F48B}\x{200D}[\x{1F468}\x{1F469}]|[\x{1F468}\x{1F469}]))|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FF}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FE}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FD}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FC}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FB}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F9D1}(?:\x{200D}(?:\x{1F91D}\x{200D}\x{1F9D1}|[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F3FF}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FE}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FD}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FC}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}]|\x{1F3FB}\x{200D}[\x{1F33E}\x{1F373}\x{1F37C}\x{1F384}\x{1F393}\x{1F3A4}\x{1F3A8}\x{1F3EB}\x{1F3ED}\x{1F4BB}\x{1F4BC}\x{1F527}\x{1F52C}\x{1F680}\x{1F692}\x{1F9AF}-\x{1F9B3}\x{1F9BC}\x{1F9BD}])|\x{1F469}\x{200D}\x{1F466}\x{200D}\x{1F466}|\x{1F469}\x{200D}\x{1F469}\x{200D}[\x{1F466}\x{1F467}]|\x{1F469}\x{200D}\x{1F467}\x{200D}[\x{1F466}\x{1F467}]|(?:\x{1F441}\x{FE0F}?\x{200D}\x{1F5E8}|\x{1F9D1}(?:\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FB}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{200D}[\x{2695}\x{2696}\x{2708}])|\x{1F469}(?:\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FB}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{200D}[\x{2695}\x{2696}\x{2708}])|\x{1F636}\x{200D}\x{1F32B}|\x{1F3F3}\x{FE0F}?\x{200D}\x{26A7}|\x{1F43B}\x{200D}\x{2744}|(?:[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93D}\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}][\x{1F3FB}-\x{1F3FF}]|[\x{1F46F}\x{1F9DE}\x{1F9DF}])\x{200D}[\x{2640}\x{2642}]|[\x{26F9}\x{1F3CB}\x{1F3CC}\x{1F575}](?:[\x{FE0F}\x{1F3FB}-\x{1F3FF}]\x{200D}[\x{2640}\x{2642}]|\x{200D}[\x{2640}\x{2642}])|\x{1F3F4}\x{200D}\x{2620}|[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93C}-\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}]\x{200D}[\x{2640}\x{2642}]|[\xA9\xAE\x{203C}\x{2049}\x{2122}\x{2139}\x{2194}-\x{2199}\x{21A9}\x{21AA}\x{231A}\x{231B}\x{2328}\x{23CF}\x{23ED}-\x{23EF}\x{23F1}\x{23F2}\x{23F8}-\x{23FA}\x{24C2}\x{25AA}\x{25AB}\x{25B6}\x{25C0}\x{25FB}\x{25FC}\x{25FE}\x{2600}-\x{2604}\x{260E}\x{2611}\x{2614}\x{2615}\x{2618}\x{2620}\x{2622}\x{2623}\x{2626}\x{262A}\x{262E}\x{262F}\x{2638}-\x{263A}\x{2640}\x{2642}\x{2648}-\x{2653}\x{265F}\x{2660}\x{2663}\x{2665}\x{2666}\x{2668}\x{267B}\x{267E}\x{267F}\x{2692}\x{2694}-\x{2697}\x{2699}\x{269B}\x{269C}\x{26A0}\x{26A7}\x{26AA}\x{26B0}\x{26B1}\x{26BD}\x{26BE}\x{26C4}\x{26C8}\x{26CF}\x{26D1}\x{26D3}\x{26E9}\x{26F0}-\x{26F5}\x{26F7}\x{26F8}\x{26FA}\x{2702}\x{2708}\x{2709}\x{270F}\x{2712}\x{2714}\x{2716}\x{271D}\x{2721}\x{2733}\x{2734}\x{2744}\x{2747}\x{2763}\x{27A1}\x{2934}\x{2935}\x{2B05}-\x{2B07}\x{2B1B}\x{2B1C}\x{2B55}\x{3030}\x{303D}\x{3297}\x{3299}\x{1F004}\x{1F170}\x{1F171}\x{1F17E}\x{1F17F}\x{1F202}\x{1F237}\x{1F321}\x{1F324}-\x{1F32C}\x{1F336}\x{1F37D}\x{1F396}\x{1F397}\x{1F399}-\x{1F39B}\x{1F39E}\x{1F39F}\x{1F3CD}\x{1F3CE}\x{1F3D4}-\x{1F3DF}\x{1F3F5}\x{1F3F7}\x{1F43F}\x{1F4FD}\x{1F549}\x{1F54A}\x{1F56F}\x{1F570}\x{1F573}\x{1F576}-\x{1F579}\x{1F587}\x{1F58A}-\x{1F58D}\x{1F5A5}\x{1F5A8}\x{1F5B1}\x{1F5B2}\x{1F5BC}\x{1F5C2}-\x{1F5C4}\x{1F5D1}-\x{1F5D3}\x{1F5DC}-\x{1F5DE}\x{1F5E1}\x{1F5E3}\x{1F5E8}\x{1F5EF}\x{1F5F3}\x{1F5FA}\x{1F6CB}\x{1F6CD}-\x{1F6CF}\x{1F6E0}-\x{1F6E5}\x{1F6E9}\x{1F6F0}\x{1F6F3}])\x{FE0F}|\x{1F441}\x{FE0F}?\x{200D}\x{1F5E8}|\x{1F9D1}(?:\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FB}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{200D}[\x{2695}\x{2696}\x{2708}])|\x{1F469}(?:\x{1F3FF}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FE}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FD}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FC}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{1F3FB}\x{200D}[\x{2695}\x{2696}\x{2708}]|\x{200D}[\x{2695}\x{2696}\x{2708}])|\x{1F3F3}\x{FE0F}?\x{200D}\x{1F308}|\x{1F469}\x{200D}\x{1F467}|\x{1F469}\x{200D}\x{1F466}|\x{1F636}\x{200D}\x{1F32B}|\x{1F3F3}\x{FE0F}?\x{200D}\x{26A7}|\x{1F635}\x{200D}\x{1F4AB}|\x{1F62E}\x{200D}\x{1F4A8}|\x{1F415}\x{200D}\x{1F9BA}|\x{1FAF1}(?:\x{1F3FF}|\x{1F3FE}|\x{1F3FD}|\x{1F3FC}|\x{1F3FB})?|\x{1F9D1}(?:\x{1F3FF}|\x{1F3FE}|\x{1F3FD}|\x{1F3FC}|\x{1F3FB})?|\x{1F469}(?:\x{1F3FF}|\x{1F3FE}|\x{1F3FD}|\x{1F3FC}|\x{1F3FB})?|\x{1F43B}\x{200D}\x{2744}|(?:[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93D}\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}][\x{1F3FB}-\x{1F3FF}]|[\x{1F46F}\x{1F9DE}\x{1F9DF}])\x{200D}[\x{2640}\x{2642}]|[\x{26F9}\x{1F3CB}\x{1F3CC}\x{1F575}](?:[\x{FE0F}\x{1F3FB}-\x{1F3FF}]\x{200D}[\x{2640}\x{2642}]|\x{200D}[\x{2640}\x{2642}])|\x{1F3F4}\x{200D}\x{2620}|\x{1F1FD}\x{1F1F0}|\x{1F1F6}\x{1F1E6}|\x{1F1F4}\x{1F1F2}|\x{1F408}\x{200D}\x{2B1B}|\x{2764}(?:\x{FE0F}\x{200D}[\x{1F525}\x{1FA79}]|\x{200D}[\x{1F525}\x{1FA79}])|\x{1F441}\x{FE0F}?|\x{1F3F3}\x{FE0F}?|[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93C}-\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}]\x{200D}[\x{2640}\x{2642}]|\x{1F1FF}[\x{1F1E6}\x{1F1F2}\x{1F1FC}]|\x{1F1FE}[\x{1F1EA}\x{1F1F9}]|\x{1F1FC}[\x{1F1EB}\x{1F1F8}]|\x{1F1FB}[\x{1F1E6}\x{1F1E8}\x{1F1EA}\x{1F1EC}\x{1F1EE}\x{1F1F3}\x{1F1FA}]|\x{1F1FA}[\x{1F1E6}\x{1F1EC}\x{1F1F2}\x{1F1F3}\x{1F1F8}\x{1F1FE}\x{1F1FF}]|\x{1F1F9}[\x{1F1E6}\x{1F1E8}\x{1F1E9}\x{1F1EB}-\x{1F1ED}\x{1F1EF}-\x{1F1F4}\x{1F1F7}\x{1F1F9}\x{1F1FB}\x{1F1FC}\x{1F1FF}]|\x{1F1F8}[\x{1F1E6}-\x{1F1EA}\x{1F1EC}-\x{1F1F4}\x{1F1F7}-\x{1F1F9}\x{1F1FB}\x{1F1FD}-\x{1F1FF}]|\x{1F1F7}[\x{1F1EA}\x{1F1F4}\x{1F1F8}\x{1F1FA}\x{1F1FC}]|\x{1F1F5}[\x{1F1E6}\x{1F1EA}-\x{1F1ED}\x{1F1F0}-\x{1F1F3}\x{1F1F7}-\x{1F1F9}\x{1F1FC}\x{1F1FE}]|\x{1F1F3}[\x{1F1E6}\x{1F1E8}\x{1F1EA}-\x{1F1EC}\x{1F1EE}\x{1F1F1}\x{1F1F4}\x{1F1F5}\x{1F1F7}\x{1F1FA}\x{1F1FF}]|\x{1F1F2}[\x{1F1E6}\x{1F1E8}-\x{1F1ED}\x{1F1F0}-\x{1F1FF}]|\x{1F1F1}[\x{1F1E6}-\x{1F1E8}\x{1F1EE}\x{1F1F0}\x{1F1F7}-\x{1F1FB}\x{1F1FE}]|\x{1F1F0}[\x{1F1EA}\x{1F1EC}-\x{1F1EE}\x{1F1F2}\x{1F1F3}\x{1F1F5}\x{1F1F7}\x{1F1FC}\x{1F1FE}\x{1F1FF}]|\x{1F1EF}[\x{1F1EA}\x{1F1F2}\x{1F1F4}\x{1F1F5}]|\x{1F1EE}[\x{1F1E8}-\x{1F1EA}\x{1F1F1}-\x{1F1F4}\x{1F1F6}-\x{1F1F9}]|\x{1F1ED}[\x{1F1F0}\x{1F1F2}\x{1F1F3}\x{1F1F7}\x{1F1F9}\x{1F1FA}]|\x{1F1EC}[\x{1F1E6}\x{1F1E7}\x{1F1E9}-\x{1F1EE}\x{1F1F1}-\x{1F1F3}\x{1F1F5}-\x{1F1FA}\x{1F1FC}\x{1F1FE}]|\x{1F1EB}[\x{1F1EE}-\x{1F1F0}\x{1F1F2}\x{1F1F4}\x{1F1F7}]|\x{1F1EA}[\x{1F1E6}\x{1F1E8}\x{1F1EA}\x{1F1EC}\x{1F1ED}\x{1F1F7}-\x{1F1FA}]|\x{1F1E9}[\x{1F1EA}\x{1F1EC}\x{1F1EF}\x{1F1F0}\x{1F1F2}\x{1F1F4}\x{1F1FF}]|\x{1F1E8}[\x{1F1E6}\x{1F1E8}\x{1F1E9}\x{1F1EB}-\x{1F1EE}\x{1F1F0}-\x{1F1F5}\x{1F1F7}\x{1F1FA}-\x{1F1FF}]|\x{1F1E7}[\x{1F1E6}\x{1F1E7}\x{1F1E9}-\x{1F1EF}\x{1F1F1}-\x{1F1F4}\x{1F1F6}-\x{1F1F9}\x{1F1FB}\x{1F1FC}\x{1F1FE}\x{1F1FF}]|\x{1F1E6}[\x{1F1E8}-\x{1F1EC}\x{1F1EE}\x{1F1F1}\x{1F1F2}\x{1F1F4}\x{1F1F6}-\x{1F1FA}\x{1F1FC}\x{1F1FD}\x{1F1FF}]|[#\*0-9]\x{FE0F}?\x{20E3}|\x{1F93C}[\x{1F3FB}-\x{1F3FF}]|\x{2764}\x{FE0F}?|[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93D}\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}][\x{1F3FB}-\x{1F3FF}]|[\x{26F9}\x{1F3CB}\x{1F3CC}\x{1F575}][\x{FE0F}\x{1F3FB}-\x{1F3FF}]?|\x{1F3F4}|[\x{270A}\x{270B}\x{1F385}\x{1F3C2}\x{1F3C7}\x{1F442}\x{1F443}\x{1F446}-\x{1F450}\x{1F466}\x{1F467}\x{1F46B}-\x{1F46D}\x{1F472}\x{1F474}-\x{1F476}\x{1F478}\x{1F47C}\x{1F483}\x{1F485}\x{1F48F}\x{1F491}\x{1F4AA}\x{1F57A}\x{1F595}\x{1F596}\x{1F64C}\x{1F64F}\x{1F6C0}\x{1F6CC}\x{1F90C}\x{1F90F}\x{1F918}-\x{1F91F}\x{1F930}-\x{1F934}\x{1F936}\x{1F977}\x{1F9B5}\x{1F9B6}\x{1F9BB}\x{1F9D2}\x{1F9D3}\x{1F9D5}\x{1FAC3}-\x{1FAC5}\x{1FAF0}\x{1FAF2}-\x{1FAF6}][\x{1F3FB}-\x{1F3FF}]|[\x{261D}\x{270C}\x{270D}\x{1F574}\x{1F590}][\x{FE0F}\x{1F3FB}-\x{1F3FF}]|[\x{261D}\x{270A}-\x{270D}\x{1F385}\x{1F3C2}\x{1F3C7}\x{1F408}\x{1F415}\x{1F43B}\x{1F442}\x{1F443}\x{1F446}-\x{1F450}\x{1F466}\x{1F467}\x{1F46B}-\x{1F46D}\x{1F472}\x{1F474}-\x{1F476}\x{1F478}\x{1F47C}\x{1F483}\x{1F485}\x{1F48F}\x{1F491}\x{1F4AA}\x{1F574}\x{1F57A}\x{1F590}\x{1F595}\x{1F596}\x{1F62E}\x{1F635}\x{1F636}\x{1F64C}\x{1F64F}\x{1F6C0}\x{1F6CC}\x{1F90C}\x{1F90F}\x{1F918}-\x{1F91F}\x{1F930}-\x{1F934}\x{1F936}\x{1F93C}\x{1F977}\x{1F9B5}\x{1F9B6}\x{1F9BB}\x{1F9D2}\x{1F9D3}\x{1F9D5}\x{1FAC3}-\x{1FAC5}\x{1FAF0}\x{1FAF2}-\x{1FAF6}]|[\x{1F3C3}\x{1F3C4}\x{1F3CA}\x{1F46E}\x{1F470}\x{1F471}\x{1F473}\x{1F477}\x{1F481}\x{1F482}\x{1F486}\x{1F487}\x{1F645}-\x{1F647}\x{1F64B}\x{1F64D}\x{1F64E}\x{1F6A3}\x{1F6B4}-\x{1F6B6}\x{1F926}\x{1F935}\x{1F937}-\x{1F939}\x{1F93D}\x{1F93E}\x{1F9B8}\x{1F9B9}\x{1F9CD}-\x{1F9CF}\x{1F9D4}\x{1F9D6}-\x{1F9DD}]|[\x{1F46F}\x{1F9DE}\x{1F9DF}]|[\xA9\xAE\x{203C}\x{2049}\x{2122}\x{2139}\x{2194}-\x{2199}\x{21A9}\x{21AA}\x{231A}\x{231B}\x{2328}\x{23CF}\x{23ED}-\x{23EF}\x{23F1}\x{23F2}\x{23F8}-\x{23FA}\x{24C2}\x{25AA}\x{25AB}\x{25B6}\x{25C0}\x{25FB}\x{25FC}\x{25FE}\x{2600}-\x{2604}\x{260E}\x{2611}\x{2614}\x{2615}\x{2618}\x{2620}\x{2622}\x{2623}\x{2626}\x{262A}\x{262E}\x{262F}\x{2638}-\x{263A}\x{2640}\x{2642}\x{2648}-\x{2653}\x{265F}\x{2660}\x{2663}\x{2665}\x{2666}\x{2668}\x{267B}\x{267E}\x{267F}\x{2692}\x{2694}-\x{2697}\x{2699}\x{269B}\x{269C}\x{26A0}\x{26A7}\x{26AA}\x{26B0}\x{26B1}\x{26BD}\x{26BE}\x{26C4}\x{26C8}\x{26CF}\x{26D1}\x{26D3}\x{26E9}\x{26F0}-\x{26F5}\x{26F7}\x{26F8}\x{26FA}\x{2702}\x{2708}\x{2709}\x{270F}\x{2712}\x{2714}\x{2716}\x{271D}\x{2721}\x{2733}\x{2734}\x{2744}\x{2747}\x{2763}\x{27A1}\x{2934}\x{2935}\x{2B05}-\x{2B07}\x{2B1B}\x{2B1C}\x{2B55}\x{3030}\x{303D}\x{3297}\x{3299}\x{1F004}\x{1F170}\x{1F171}\x{1F17E}\x{1F17F}\x{1F202}\x{1F237}\x{1F321}\x{1F324}-\x{1F32C}\x{1F336}\x{1F37D}\x{1F396}\x{1F397}\x{1F399}-\x{1F39B}\x{1F39E}\x{1F39F}\x{1F3CD}\x{1F3CE}\x{1F3D4}-\x{1F3DF}\x{1F3F5}\x{1F3F7}\x{1F43F}\x{1F4FD}\x{1F549}\x{1F54A}\x{1F56F}\x{1F570}\x{1F573}\x{1F576}-\x{1F579}\x{1F587}\x{1F58A}-\x{1F58D}\x{1F5A5}\x{1F5A8}\x{1F5B1}\x{1F5B2}\x{1F5BC}\x{1F5C2}-\x{1F5C4}\x{1F5D1}-\x{1F5D3}\x{1F5DC}-\x{1F5DE}\x{1F5E1}\x{1F5E3}\x{1F5E8}\x{1F5EF}\x{1F5F3}\x{1F5FA}\x{1F6CB}\x{1F6CD}-\x{1F6CF}\x{1F6E0}-\x{1F6E5}\x{1F6E9}\x{1F6F0}\x{1F6F3}]|[\x{23E9}-\x{23EC}\x{23F0}\x{23F3}\x{25FD}\x{2693}\x{26A1}\x{26AB}\x{26C5}\x{26CE}\x{26D4}\x{26EA}\x{26FD}\x{2705}\x{2728}\x{274C}\x{274E}\x{2753}-\x{2755}\x{2757}\x{2795}-\x{2797}\x{27B0}\x{27BF}\x{2B50}\x{1F0CF}\x{1F18E}\x{1F191}-\x{1F19A}\x{1F201}\x{1F21A}\x{1F22F}\x{1F232}-\x{1F236}\x{1F238}-\x{1F23A}\x{1F250}\x{1F251}\x{1F300}-\x{1F320}\x{1F32D}-\x{1F335}\x{1F337}-\x{1F37C}\x{1F37E}-\x{1F384}\x{1F386}-\x{1F393}\x{1F3A0}-\x{1F3C1}\x{1F3C5}\x{1F3C6}\x{1F3C8}\x{1F3C9}\x{1F3CF}-\x{1F3D3}\x{1F3E0}-\x{1F3F0}\x{1F3F8}-\x{1F407}\x{1F409}-\x{1F414}\x{1F416}-\x{1F43A}\x{1F43C}-\x{1F43E}\x{1F440}\x{1F444}\x{1F445}\x{1F451}-\x{1F465}\x{1F46A}\x{1F479}-\x{1F47B}\x{1F47D}-\x{1F480}\x{1F484}\x{1F488}-\x{1F48E}\x{1F490}\x{1F492}-\x{1F4A9}\x{1F4AB}-\x{1F4FC}\x{1F4FF}-\x{1F53D}\x{1F54B}-\x{1F54E}\x{1F550}-\x{1F567}\x{1F5A4}\x{1F5FB}-\x{1F62D}\x{1F62F}-\x{1F634}\x{1F637}-\x{1F644}\x{1F648}-\x{1F64A}\x{1F680}-\x{1F6A2}\x{1F6A4}-\x{1F6B3}\x{1F6B7}-\x{1F6BF}\x{1F6C1}-\x{1F6C5}\x{1F6D0}-\x{1F6D2}\x{1F6D5}-\x{1F6D7}\x{1F6DD}-\x{1F6DF}\x{1F6EB}\x{1F6EC}\x{1F6F4}-\x{1F6FC}\x{1F7E0}-\x{1F7EB}\x{1F7F0}\x{1F90D}\x{1F90E}\x{1F910}-\x{1F917}\x{1F920}-\x{1F925}\x{1F927}-\x{1F92F}\x{1F93A}\x{1F93F}-\x{1F945}\x{1F947}-\x{1F976}\x{1F978}-\x{1F9B4}\x{1F9B7}\x{1F9BA}\x{1F9BC}-\x{1F9CC}\x{1F9D0}\x{1F9E0}-\x{1F9FF}\x{1FA70}-\x{1FA74}\x{1FA78}-\x{1FA7C}\x{1FA80}-\x{1FA86}\x{1FA90}-\x{1FAAC}\x{1FAB0}-\x{1FABA}\x{1FAC0}-\x{1FAC2}\x{1FAD0}-\x{1FAD9}\x{1FAE0}-\x{1FAE7}]/u', '', $text);
}

function shortenClient($client)
{
    // Pre-process by removing any non-alphanumeric characters except for certain punctuations.
    $client = html_entity_decode($client); // Decode any HTML entities
    $client = str_replace("'", "", $client); // Removing all occurrences of '
    $cleaned = preg_replace('/[^a-zA-Z0-9&]+/', ' ', $client);

    // Break into words.
    $words = explode(' ', trim($cleaned));

    $shortened = '';

    // If there's only one word.
    if (count($words) == 1) {
        $word = $words[0];

        if (strlen($word) <= 3) {
            return strtoupper($word);
        }

        // Prefer starting and ending characters.
        $shortened = $word[0] . substr($word, -2);
    } else {
        // Less weightage to common words.
        $commonWords = ['the', 'of', 'and'];

        foreach ($words as $word) {
            if (!in_array(strtolower($word), $commonWords) || strlen($shortened) < 2) {
                $shortened .= $word[0];
            }
        }

        // If there are still not enough characters, take from the last word.
        while (strlen($shortened) < 3 && !empty($word)) {
            $shortened .= substr($word, 1, 1);
            $word = substr($word, 1);
        }
    }

    return strtoupper(substr($shortened, 0, 3));
}

function roundToNearest15($time)
{
    // Validate the input time format
    if (!preg_match('/^(\d{2}):(\d{2}):(\d{2})$/', $time, $matches)) {
        return false; // or throw an exception
    }

    // Extract hours, minutes, and seconds from the matched time string
    list(, $hours, $minutes, $seconds) = $matches;

    // Convert everything to seconds for easier calculation
    $totalSeconds = ($hours * 3600) + ($minutes * 60) + $seconds;

    // Calculate the remainder when divided by 900 seconds (15 minutes)
    $remainder = $totalSeconds % 900;

    if ($remainder > 450) {  // If remainder is more than 7.5 minutes (450 seconds), round up
        $totalSeconds += (900 - $remainder);
    } else {  // Else round down
        $totalSeconds -= $remainder;
    }

    // Convert total seconds to decimal hours
    $decimalHours = $totalSeconds / 3600;

    // Return the decimal hours
    return number_format($decimalHours, 2);
}

function getMonthlyTax($tax_name, $month, $year, $mysqli)
{
    // SQL to calculate monthly tax
    $sql = "SELECT SUM(item_tax) AS monthly_tax FROM invoice_items
            LEFT JOIN invoices ON invoice_items.item_invoice_id = invoices.invoice_id
            LEFT JOIN payments ON invoices.invoice_id = payments.payment_invoice_id
            WHERE YEAR(payments.payment_date) = $year AND MONTH(payments.payment_date) = $month
            AND invoice_items.item_tax_id = (SELECT tax_id FROM taxes WHERE tax_name = '$tax_name')";
    $result = mysqli_query($mysqli, $sql);
    $row = mysqli_fetch_assoc($result);
    return $row['monthly_tax'] ?? 0;
}

function getQuarterlyTax($tax_name, $quarter, $year, $mysqli)
{
    // Calculate start and end months for the quarter
    $start_month = ($quarter - 1) * 3 + 1;
    $end_month = $start_month + 2;

    // SQL to calculate quarterly tax
    $sql = "SELECT SUM(item_tax) AS quarterly_tax FROM invoice_items
            LEFT JOIN invoices ON invoice_items.item_invoice_id = invoices.invoice_id
            LEFT JOIN payments ON invoices.invoice_id = payments.payment_invoice_id
            WHERE YEAR(payments.payment_date) = $year AND MONTH(payments.payment_date) BETWEEN $start_month AND $end_month
            AND invoice_items.item_tax_id = (SELECT tax_id FROM taxes WHERE tax_name = '$tax_name')";
    $result = mysqli_query($mysqli, $sql);
    $row = mysqli_fetch_assoc($result);
    return $row['quarterly_tax'] ?? 0;
}

function getTotalTax($tax_name, $year, $mysqli)
{
    // SQL to calculate total tax
    $sql = "SELECT SUM(item_tax) AS total_tax FROM invoice_items
            LEFT JOIN invoices ON invoice_items.item_invoice_id = invoices.invoice_id
            LEFT JOIN payments ON invoices.invoice_id = payments.payment_invoice_id
            WHERE YEAR(payments.payment_date) = $year
            AND invoice_items.item_tax_id = (SELECT tax_id FROM taxes WHERE tax_name = '$tax_name')";
    $result = mysqli_query($mysqli, $sql);
    $row = mysqli_fetch_assoc($result);
    return $row['total_tax'] ?? 0;
}

function generateReadablePassword($security_level)
{
    // Cap security level at 5
    $security_level = intval($security_level);
    $security_level = min($security_level, 5);

    // Arrays of words
    $articles = ['The', 'A'];
    $adjectives = ['Smart', 'Swift', 'Secure', 'Stable', 'Digital', 'Virtual', 'Active', 'Dynamic', 'Innovative', 'Efficient', 'Portable', 'Wireless', 'Rapid', 'Intuitive', 'Automated', 'Robust', 'Reliable', 'Sleek', 'Modern', 'Happy', 'Funny', 'Quick', 'Bright', 'Clever', 'Gentle', 'Brave', 'Calm', 'Eager', 'Fierce', 'Kind', 'Lucky', 'Proud', 'Silly', 'Witty', 'Bold', 'Curious', 'Elated', 'Gracious', 'Honest', 'Jolly', 'Merry', 'Noble', 'Optimistic', 'Playful', 'Quirky', 'Rustic', 'Steady', 'Tranquil', 'Upbeat'];
    $nouns = ['Computer', 'Laptop', 'Tablet', 'Server', 'Router', 'Software', 'Hardware', 'Pixel', 'Byte', 'App', 'Network', 'Cloud', 'Firewall', 'Email', 'Database', 'Folder', 'Document', 'Interface', 'Program', 'Gadget', 'Dinosaur', 'Tiger', 'Elephant', 'Kangaroo', 'Monkey', 'Unicorn', 'Dragon', 'Puppy', 'Kitten', 'Parrot', 'Lion', 'Bear', 'Fox', 'Wolf', 'Rabbit', 'Deer', 'Owl', 'Hedgehog', 'Turtle', 'Frog', 'Butterfly', 'Panda', 'Giraffe', 'Zebra', 'Peacock', 'Koala', 'Raccoon', 'Squirrel', 'Hippo', 'Rhino', 'Book', "Monitor"];
    $verbs = ['Connects', 'Runs', 'Processes', 'Secures', 'Encrypts', 'Saves', 'Updates', 'Boots', 'Scans', 'Compiles', 'Executes', 'Restores', 'Installs', 'Configures', 'Downloads', 'Streams', 'BacksUp', 'Syncs', 'Browses', 'Navigates', 'Runs', 'Jumps', 'Flies', 'Swims', 'Dances', 'Sings', 'Hops', 'Skips', 'Races', 'Climbs', 'Crawls', 'Glides', 'Twirls', 'Swings', 'Sprints', 'Gallops', 'Trots', 'Wanders', 'Strolls', 'Marches'];
    $adverbs = ['Quickly', 'Slowly', 'Gracefully', 'Wildly', 'Loudly', 'Silently', 'Cheerfully', 'Eagerly', 'Gently', 'Happily', 'Jovially', 'Kindly', 'Lazily', 'Merrily', 'Neatly', 'Politely', 'Quietly', 'Rapidly', 'Smoothly', 'Tightly', 'Swiftly', 'Securely', 'Efficiently', 'Rapidly', 'Smoothly', 'Reliably', 'Safely', 'Wirelessly', 'Instantly', 'Silently', 'Automatically', 'Seamlessly', 'Digitally', 'Virtually', 'Continuously', 'Regularly', 'Intelligently', 'Logically'];

    // Randomly select words from arrays
    $adj = $adjectives[array_rand($adjectives)];
    $noun = $nouns[array_rand($nouns)];
    $verb = $verbs[array_rand($verbs)];
    $adv = $adverbs[array_rand($adverbs)];

    // Combine to create a base password
    $password = $adj . $noun . $verb . $adv;

    // Select an article randomly
    $article = $articles[array_rand($articles)];

    // Determine if we should use 'An' instead of 'A'
    if ($article == 'A' && preg_match('/^[aeiouAEIOU]/', $adj)) {
        $article = 'An';
    }

    // Add the article to the password
    $password = $article . $password;

    // Mapping of letters to special characters and numbers
    $mappings = [
        'A' => '@', 'a' => '@',
        'E' => '3', 'e' => '3',
        'I' => '!', 'i' => '!',
        'O' => '0', 'o' => '0',
        'S' => '$', 's' => '$',
        'T' => '+', 't' => '+',
        'B' => '8', 'b' => '8'
    ];

    // Generate an array of indices based on the password length
    $indices = range(0, strlen($password) - 1);
    // Randomly shuffle the indices
    shuffle($indices);

    // Iterate through the shuffled indices and replace characters based on the security level
    for ($i = 0; $i < min($security_level, strlen($password)); $i++) {
        $index = $indices[$i]; // Get a random index
        $currentChar = $password[$index]; // Get the character at this index
        // Check if the current character has a mapping and replace it
        if (array_key_exists($currentChar, $mappings)) {
            $password[$index] = $mappings[$currentChar];
        }
    }

    // Add as many random numbers as the security level
    $password .= rand(pow(10, $security_level - 1), pow(10, $security_level) - 1);

    return $password;
}

function addToMailQueue($data) {

    global $mysqli;

    foreach ($data as $email) {
        $from = strval($email['from']);
        $from_name = strval($email['from_name']);
        $recipient = strval($email['recipient']);
        $recipient_name = strval($email['recipient_name']);
        $subject = strval($email['subject']);
        $body = strval($email['body']);

        $cal_str = '';
        if (isset($email['cal_str'])) {
            $cal_str = mysqli_escape_string($mysqli, $email['cal_str']);
        }

        // Check if 'email_queued_at' is set and not empty
        if (isset($email['queued_at']) && !empty($email['queued_at'])) {
            $queued_at = "'" . sanitizeInput($email['queued_at']) . "'";
        } else {
            // Use the current date and time if 'email_queued_at' is not set or empty
            $queued_at = 'CURRENT_TIMESTAMP()';
        }

        mysqli_query($mysqli, "INSERT INTO email_queue SET email_recipient = '$recipient', email_recipient_name = '$recipient_name', email_from = '$from', email_from_name = '$from_name', email_subject = '$subject', email_content = '$body', email_queued_at = $queued_at, email_cal_str = '$cal_str'");
    }

    return true;
}

function createiCalStr($datetime, $title, $description, $location)
{
    require_once "plugins/zapcal/zapcallib.php";

    // Create the iCal object
    $cal_event = new ZCiCal();
    $event = new ZCiCalNode("VEVENT", $cal_event->curnode);


    // Set the method to REQUEST to indicate an invite
    $event->addNode(new ZCiCalDataNode("METHOD:REQUEST"));
    $event->addNode(new ZCiCalDataNode("SUMMARY:" . $title));
    $event->addNode(new ZCiCalDataNode("DTSTART:" . ZCiCal::fromSqlDateTime($datetime)));
    // Assuming the end time is the same as start time.
    // Todo: adjust this for actual duration
    $event->addNode(new ZCiCalDataNode("DTEND:" . ZCiCal::fromSqlDateTime($datetime)));
    $event->addNode(new ZCiCalDataNode("DTSTAMP:" . ZCiCal::fromSqlDateTime()));
    $uid = date('Y-m-d-H-i-s') . "@" . $_SERVER['SERVER_NAME'];
    $event->addNode(new ZCiCalDataNode("UID:" . $uid));
    $event->addNode(new ZCiCalDataNode("LOCATION:" . $location));
    $event->addNode(new ZCiCalDataNode("DESCRIPTION:" . $description));
    // Todo: add organizer details
    // $event->addNode(new ZCiCalDataNode("ORGANIZER;CN=Organizer Name:MAILTO:organizer@example.com"));

    // Return the iCal string
    return $cal_event->export();
}

function isMobile()
{
    // Check if the user agent is a mobile device
    return preg_match('/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|opera mini|palm|phone|pie|tablet|up.browser|up.link|webos|wos)/i', $_SERVER['HTTP_USER_AGENT']);
}

function createiCalStrCancel($originaliCalStr) {
    require_once "plugins/zapcal/zapcallib.php";

    // Import the original iCal string
    $cal_event = new ZCiCal($originaliCalStr);

    // Iterate through the iCalendar object to find VEVENT nodes
    foreach($cal_event->tree->child as $node) {
        if($node->getName() == "VEVENT") {
            // Check if STATUS node exists, update it, or add a new one
            $statusFound = false;
            foreach($node->data as $key => $value) {
                if($key == "STATUS") {
                    $value->setValue("CANCELLED");
                    $statusFound = true;
                    break; // Exit the loop once the STATUS is updated
                }
            }
            // If STATUS node is not found, add a new STATUS node
            if (!$statusFound) {
                $node->addNode(new ZCiCalDataNode("STATUS:CANCELLED"));
            }
        }
    }

    // Return the modified iCal string
    return $cal_event->export();
}

function getTicketStatusName($ticket_status) {

    global $mysqli;

    $status_id = intval($ticket_status);
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT * FROM ticket_statuses WHERE ticket_status_id = $status_id LIMIT 1"));

    if ($row) {
        return nullable_htmlentities($row['ticket_status_name']);
    }

    // Default return
    return "Unknown";

}


function fetchUpdates() {

    global $repo_branch;

    // Fetch the latest code changes but don't apply them
    exec("git fetch", $output, $result);
    $latest_version = exec("git rev-parse origin/$repo_branch");
    $current_version = exec("git rev-parse HEAD");

    if ($current_version == $latest_version) {
        $update_message = "No Updates available";
    } else {
        $update_message = "New Updates are Available [$latest_version]";
    }


    $updates = new stdClass();
    $updates->output = $output;
    $updates->result = $result;
    $updates->current_version = $current_version;
    $updates->latest_version = $latest_version;
    $updates->update_message = $update_message;


    return $updates;

}

function getDomainExpirationDate($domain) {
    // Execute the whois command
    $result = shell_exec("whois " . escapeshellarg($domain));
    if (!$result || !checkdnsrr($domain, 'SOA')) {
        return null; // Return null if WHOIS query fails
    }

    $expireDate = '';

    // Regular expressions to match different date formats
    $patterns = [
        '/Expiration Date: (.+)/',
        '/Registry Expiry Date: (.+)/',
        '/expires: (.+)/',
        '/Expiry Date: (.+)/',
        '/renewal date: (.+)/',
        '/Expires On: (.+)/',
        '/paid-till: (.+)/',
        '/Expiration Time: (.+)/',
        '/\[Expires on\]\s+(.+)/',
        '/expire: (.+)/',
        '/validity: (.+)/',
        '/Expires on.*: (.+)/i',
        '/Expiry on.*: (.+)/i',
        '/renewal: (.+)/i',
        '/Expir\w+ Date: (.+)/i',
        '/Valid Until: (.+)/i',
        '/Valid until: (.+)/i',
        '/expire-date: (.+)/i',
        '/Expiration Date: (.+)/i',
        '/Registry Expiry Date: (.+)/i',
        '/Expire Date: (.+)/i',
        '/expiry: (.+)/i',
        '/expires: (.+)/i',
        '/Registry Expiry Date: (.+)/i',
        '/Expiration Time: (.+)/i',
        '/validity: (.+)/i',
        '/expires: (.+)/i',
        '/paid-till: (.+)/i',
        '/Expire Date: (.+)/i',
        '/Expiration Date: (.+)/i',
        '/expire: (.+)/i',
        '/expiry: (.+)/i',
        '/renewal date: (.+)/i',
        '/Expiration Date: (.+)/i',
        '/Expiration Time: (.+)/i',
        '/Expires: (.+)/i',
    ];

    // Known date formats
    $knownFormats = [
        "d-M-Y",
        "d-F-Y",
        "d-m-Y",
        "Y-m-d",
        "d.m.Y",
        "Y.m.d",
        "Y/m/d",
        "Y/m/d H:i:s",
        "Ymd",
        "Ymd H:i:s",
        "d/m/Y",
        "Y. m. d.",
        "Y.m.d H:i:s",
        "d-M-Y H:i:s",
        "D M d H:i:s T Y",
        "D M d Y",
        "Y-m-d\TH:i:s",
        "Y-m-d\TH:i:s\Z",
        "Y-m-d H:i:s\Z",
        "Y-m-d H:i:s",
        "d M Y H:i:s",
        "d/m/Y H:i:s",
        "d/m/Y H:i:s T",
        "B d Y",
        "d.m.Y H:i:s",
        "before M-Y",
        "before Y-m-d",
        "before Ymd",
        "Y-m-d H:i:s (\T\Z\Z)",
        "Y-M-d.",
    ];

    // Check each pattern to find a match
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $result, $matches)) {
            $expireDate = trim($matches[1]);
            break;
        }
    }

    if ($expireDate) {
        // Try parsing with known formats
        foreach ($knownFormats as $format) {
            $parsedDate = DateTime::createFromFormat($format, $expireDate);
            if ($parsedDate && $parsedDate->format($format) === $expireDate) {
                return $parsedDate->format('Y-m-d');
            }
        }

        // If none of the formats matched, try to parse it directly
        $parsedDate = date_create($expireDate);
        if ($parsedDate) {
            return $parsedDate->format('Y-m-d');
        }
    }

    return null; // Return null if expiration date is not found
}

function validateWhitelabelKey($key)
{
    $public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0k+4ZJudkdGMCFLx5b9
H/sOozvWphFJsjVIF0vPVx9J0bTdml65UdS+32JagIHfPtEUTohaMnI3IAxxCDzl
655qmtjL7RHHdx9UMIKCmtAZOtd2u6rEyZH7vB7cKA49ysKGIaQSGwTQc8DCgsrK
uxRuX04xq9T7T+zuzROw3Y9WjFy9RwrONqLuG8LqO0j7bk5LKYeLAV7u3E/QiqNx
lEljN2UVJ3FZ/LkXeg8ORkV+IHs/toRIfPs/4VQnjEwk5BU6DX2STOvbeZnTqwP3
zgjRYR/zGN5l+az6RB3+0mJRdZdv/y2aRkBlwTxx2gOrPbQAco4a/IOmkE3EbHe7
6wIDAQAP
-----END PUBLIC KEY-----";

    if (openssl_public_decrypt(base64_decode($key), $decrypted, $public_key)) {
        $key_info = json_decode($decrypted, true);
        if ($key_info['expires'] > date('Y-m-d H:i:s', strtotime('-7 day'))) {
            return $key_info;
        }
    }

    return false;
}

// When provided a module name (e.g. module_support), returns the associated permission level (false=none, 1=read, 2=write, 3=full)
function lookupUserPermission($module) {
    global $mysqli, $session_is_admin, $session_user_role;

    if (isset($session_is_admin) && $session_is_admin === true) {
        return 3;
    }

    $module = sanitizeInput($module);

    $sql = mysqli_query(
        $mysqli,
        "SELECT
			user_role_permissions.user_role_permission_level
		FROM
			modules
		JOIN
			user_role_permissions
		ON
			modules.module_id = user_role_permissions.module_id
		WHERE
			module_name = '$module' AND user_role_permissions.user_role_id = $session_user_role"
    );

    $row = mysqli_fetch_assoc($sql);

    if (isset($row['user_role_permission_level'])) {
        return intval($row['user_role_permission_level']);
    }

    // Default return for no module permission
    return false;
}

// Ensures a user has access to a module (e.g. module_support) with at least the required permission level provided (defaults to read)
function enforceUserPermission($module, $check_access_level = 1) {
    $permitted_access_level = lookupUserPermission($module);

    if (!$permitted_access_level || $permitted_access_level < $check_access_level) {
        $_SESSION['alert_type'] = "danger";
        $_SESSION['alert_message'] = WORDING_ROLECHECK_FAILED;
        $map = [
            "1" => "read",
            "2" => "write",
            "3" => "full"
        ];
        exit(WORDING_ROLECHECK_FAILED . "<br>Tell your admin: $map[$check_access_level] access to $module is not permitted for your role.");
    }
}

function enforceClientAccess($client_id = null) {
    global $mysqli, $session_user_id, $session_is_admin, $session_name;

    // Use global $client_id if none passed
    if ($client_id === null) {
        global $client_id;
    }

    if ($session_is_admin) {
        return true;
    }

    $client_id = (int) $client_id;
    $session_user_id = (int) $session_user_id;

    if (empty($client_id) || empty($session_user_id)) {
        flash_alert('Access Denied.', 'error');
        redirect('clients.php');
    }

    // Check if this user has any client permissions set
    $permissions_sql = "SELECT client_id
                        FROM user_client_permissions
                        WHERE user_id = $session_user_id
                        LIMIT 1";

    $permissions_result = mysqli_query($mysqli, $permissions_sql);

    // If no permission rows exist for this user, allow access by default
    if ($permissions_result && mysqli_num_rows($permissions_result) == 0) {
        return true;
    }

    // If permission rows exist, require this client
    $access_sql = "SELECT client_id
                   FROM user_client_permissions
                   WHERE user_id = $session_user_id
                   AND client_id = $client_id
                   LIMIT 1";

    $access_result = mysqli_query($mysqli, $access_sql);

    if ($access_result && mysqli_num_rows($access_result) > 0) {
        return true;
    }

    logAction(
        'Client',
        'Access',
        "$session_name was denied permission from accessing client",
        $client_id,
        $client_id
    );

    flash_alert('Access Denied - You do not have permission to access that client!', 'error');
    redirect('clients.php');
}

// TODO: Probably remove this
function enforceAdminPermission() {
    global $session_is_admin;
    if (!isset($session_is_admin) || !$session_is_admin) {
        exit(WORDING_ROLECHECK_FAILED . "<br>Tell your admin: Your role does not have admin access.");
    }
    return true;
}

function customAction($trigger, $entity) {
    $original_dir = getcwd(); // Save

    chdir(dirname(__FILE__));
    if (file_exists(__DIR__ . "/custom/custom_action_handler.php")) {
        include_once __DIR__ . "/custom/custom_action_handler.php";
    }

    chdir($original_dir); // Restore original working directory
}

function appNotify($type, $details, $action = null, $client_id = 0, $entity_id = 0) {
    global $mysqli;

    if (is_null($action)) {
        $action = "NULL"; // Without quotes for SQL NULL
    }

    $type = substr($type, 0, 200);
    $details = substr($details, 0, 1000);
    $action = substr($action, 0, 250);

    $sql = mysqli_query($mysqli, "SELECT user_id FROM users
        WHERE user_type = 1 AND user_status = 1 AND user_archived_at IS NULL
    ");

    while ($row = mysqli_fetch_assoc($sql)) {
        $user_id = intval($row['user_id']);

        mysqli_query($mysqli, "INSERT INTO notifications SET notification_type = '$type', notification = '$details', notification_action = '$action', notification_client_id = $client_id, notification_entity_id = $entity_id, notification_user_id = $user_id");
    }
}

function logAction($type, $action, $description, $client_id = 0, $entity_id = 0) {
    global $mysqli, $session_user_agent, $session_ip, $session_user_id;

    $client_id = intval($client_id);
    $entity_id = intval($entity_id);
    $session_user_id = intval($session_user_id);

    if (empty($session_user_id)) {
        $session_user_id = 0;
    }

    $type = substr($type, 0, 200);
    $action = substr($action, 0, 255);
    $description = substr($description, 0, 1000);

    mysqli_query($mysqli, "INSERT INTO logs SET log_type = '$type', log_action = '$action', log_description = '$description', log_ip = '$session_ip', log_user_agent = '$session_user_agent', log_client_id = $client_id, log_user_id = $session_user_id, log_entity_id = $entity_id");
}

function logApp($category, $type, $details) {
    global $mysqli;

    $category = substr($category, 0, 200);
    $details = substr($details, 0, 1000);

    mysqli_query($mysqli, "INSERT INTO app_logs SET app_log_category = '$category', app_log_type = '$type', app_log_details = '$details'");
}

function logAuth($status, $details) {
    global $mysqli, $session_user_agent, $session_ip, $session_user_id;

    if (empty($session_user_id)) {
        $session_user_id = 0;
    }

    mysqli_query($mysqli, "INSERT INTO auth_logs SET auth_log_status = $status, auth_log_details = '$details', auth_log_ip = '$session_ip', auth_log_user_agent = '$session_user_agent', auth_log_user_id = $session_user_id");
}

// Helper function for missing data fallback
function getFallback($data) {
    return !empty($data) ? $data : '-';
}

/**
 * Retrieves a specified field's value from a table based on the record's id.
 * It validates the table and field names, automatically determines the primary key (or uses the first column as fallback),
 * and returns the field value with an appropriate escaping method.
 *
 * @param string $table         The name of the table.
 * @param int    $id            The record's id.
 * @param string $field         The field (column) to retrieve.
 * @param string $escape_method The escape method: 'sql' (default, auto-detects int), 'html', 'json', or 'int'.
 *
 * @return mixed The escaped field value, or null if not found or invalid input.
 */
function getFieldById($table, $id, $field, $escape_method = 'sql') {
    global $mysqli;  // Use the global MySQLi connection

    // Validate table and field names to allow only letters, numbers, and underscores
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $table) || !preg_match('/^[a-zA-Z0-9_]+$/', $field)) {
        return null; // Invalid table or field name
    }

    // Sanitize id as an integer
    $id = (int)$id;

    // Get the list of columns and their details from the table
    $columns_result = mysqli_query($mysqli, "SHOW COLUMNS FROM `$table`");
    if (!$columns_result || mysqli_num_rows($columns_result) == 0) {
        return null; // Table not found or has no columns
    }

    // Build an associative array with column details
    $columns = [];
    while ($row = mysqli_fetch_assoc($columns_result)) {
        $columns[$row['Field']] = [
            'type' => $row['Type'],
            'key'  => $row['Key']
        ];
    }

    // Find the primary key field if available
    $id_field = null;
    foreach ($columns as $col => $details) {
        if ($details['key'] === 'PRI') {
            $id_field = $col;
            break;
        }
    }
    // Fallback: if no primary key is found, use the first column
    if (!$id_field) {
        reset($columns);
        $id_field = key($columns);
    }

    // Ensure the requested field exists; if not, default to the id field
    if (!array_key_exists($field, $columns)) {
        $field = $id_field;
    }

    // Build and execute the query to fetch the specified field value
    $query = "SELECT `$field` FROM `$table` WHERE `$id_field` = $id";
    $sql = mysqli_query($mysqli, $query);

    if ($sql && mysqli_num_rows($sql) > 0) {
        $row = mysqli_fetch_assoc($sql);
        $value = $row[$field];

        // Apply the desired escaping method or auto-detect integer type if using SQL escaping
        switch ($escape_method) {
            case 'raw':
                return $value; // Return as-is from the database
            case 'html':
                return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8'); // Escape for HTML
            case 'json':
                return json_encode($value); // Escape for JSON
            case 'int':
                return (int)$value; // Explicitly cast value to integer
            case 'sql':
            default:
                // Auto-detect if the field type is integer
                if (stripos($columns[$field]['type'], 'int') !== false) {
                    return (int)$value;
                } else {
                    return sanitizeInput($value); // Escape for SQL using a custom function
                }
        }
    }

    return null; // Return null if no record was found
}

// Recursive function to display folder options - Used in folders files and documents
function display_folder_options($parent_folder_id, $client_id, $indent = 0) {
    global $mysqli;

    $sql_folders = mysqli_query($mysqli, "SELECT * FROM folders WHERE parent_folder = $parent_folder_id AND folder_client_id = $client_id ORDER BY folder_name ASC");
    while ($row = mysqli_fetch_assoc($sql_folders)) {
        $folder_id = intval($row['folder_id']);
        $folder_name = nullable_htmlentities($row['folder_name']);

        // Indentation for subfolders
        $indentation = str_repeat('&nbsp;', $indent * 4);

        // Check if this folder is selected
        $selected = '';
        if ((isset($_GET['folder_id']) && intval($_GET['folder_id']) === $folder_id) ||
            (isset($_POST['folder']) && intval($_POST['folder']) === $folder_id)) {
            $selected = 'selected';
        }

        echo "<option value=\"$folder_id\" $selected>$indentation$folder_name</option>";

        // Recursively display subfolders
        display_folder_options($folder_id, $client_id, $indent + 1);
    }
}

function sanitize_url($url) {
    $allowed = ['http', 'https', 'file', 'ftp', 'ftps', 'sftp', 'dav', 'webdav', 'caldav', 'carddav',  'ssh', 'telnet', 'smb', 'rdp', 'vnc', 'rustdesk', 'anydesk', 'connectwise', 'splashtop', 'sip', 'sips', 'ldap', 'ldaps'];
    $parts = parse_url($url ?? '');
    if (isset($parts['scheme']) && !in_array(strtolower($parts['scheme']), $allowed)) {
        // Remove the scheme and colon
        $pos = strpos($url, ':');
        $without_scheme = $url;
        if ($pos !== false) {
            $without_scheme = substr($url, $pos + 1); // This keeps slashes (e.g. //pizza.com)
        }
        // Prepend 'unsupported://' (strip any leading slashes from $without_scheme to avoid triple slashes)
        $unsupported = 'unsupported://' . ltrim($without_scheme, '/');
        return htmlspecialchars($unsupported, ENT_QUOTES, 'UTF-8');
    }

    // Safe schemes: return escaped original URL
    return htmlspecialchars($url ?? '', ENT_QUOTES, 'UTF-8');
}

// Redirect Function
function redirect($url = null, $permanent = false) {
    // Use referer if no URL is provided
    if (!$url) {
        $url = $_SERVER['HTTP_REFERER'] ?? 'index.php';
    }

    if (!headers_sent()) {
        header('Location: ' . $url, true, $permanent ? 301 : 302);
        exit;
    } else {
        // Fallback for headers already sent
        echo "<script>window.location.href = '" . addslashes($url) . "';</script>";
        echo '<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($url) . '"></noscript>';
        exit;
    }
}

//Flash Alert Function
function flash_alert(string $message, string $type = 'success'): void {
    $_SESSION['alert_type'] = $type;
    $_SESSION['alert_message'] = $message;
}

// Sanitize File Names
function sanitize_filename($filename, $strict = false) {
    // Remove path information and dots around the filename
    $filename = basename($filename);

    // Replace spaces and underscores with dashes
    $filename = str_replace([' ', '_'], '-', $filename);

    // Remove anything which isn't a word, number, dot, or dash
    $filename = preg_replace('/[^A-Za-z0-9\.\-]/', '', $filename);

    // Optionally make filename strict alphanumeric (keep dot and dash)
    if ($strict) {
        $filename = preg_replace('/[^A-Za-z0-9\.\-]/', '', $filename);
    }

    // Avoid multiple consecutive dashes
    $filename = preg_replace('/-+/', '-', $filename);

    // Remove leading/trailing dots and dashes
    $filename = trim($filename, '.-');

    // Ensure it’s not empty
    if (empty($filename)) {
        $filename = 'file';
    }

    return $filename;
}

function saveBase64Images(string $html, string $baseFsPath, string $baseWebPath, int $ownerId): string {
    // Normalize paths
    $baseFsPath  = rtrim($baseFsPath, '/\\') . '/';
    $baseWebPath = rtrim($baseWebPath, '/\\') . '/';

    $targetDir = $baseFsPath . $ownerId . "/";

    $folderCreated = false;   // <-- NEW FLAG
    $savedAny      = false;   // <-- Track if ANY images processed

    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $dom->loadHTML('<?xml encoding="utf-8" ?>' . $html);
    libxml_clear_errors();

    $imgs = $dom->getElementsByTagName('img');

    foreach ($imgs as $img) {
        $src = $img->getAttribute('src');

        // Match base64 images
        if (preg_match('/^data:image\/([a-zA-Z0-9+]+);base64,(.*)$/s', $src, $matches)) {

            $savedAny = true;  // <-- We are actually saving at least 1 image

            // Create folder ONLY when needed
            if (!$folderCreated) {
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0775, true);
                }
                $folderCreated = true;
            }

            $mimeType = strtolower($matches[1]);
            $base64   = $matches[2];

            $binary = base64_decode($base64);
            if ($binary === false) {
                continue;
            }

            // Extension mapping
            switch ($mimeType) {
                case 'jpeg':
                case 'jpg': $ext = 'jpg'; break;
                case 'png': $ext = 'png'; break;
                case 'gif': $ext = 'gif'; break;
                case 'webp': $ext = 'webp'; break;
                default: $ext = 'png';
            }

            // Secure random filename
            $uid = bin2hex(random_bytes(16));
            $filename = "img_{$uid}.{$ext}";

            $filePath = $targetDir . $filename;

            if (file_put_contents($filePath, $binary) !== false) {
                $webPath = "/" . $baseWebPath . $ownerId . "/" . $filename;
                $img->setAttribute('src', $webPath);
            }
        }
    }

    // If no images were processed, return original HTML immediately
    if (!$savedAny) {
        return $html;
    }

    // Extract body content only
    $body = $dom->getElementsByTagName('body')->item(0);

    if ($body) {
        $innerHTML = '';
        foreach ($body->childNodes as $child) {
            $innerHTML .= $dom->saveHTML($child);
        }
        return $innerHTML;
    }

    return $html;
}

function cleanupUnusedImages(string $html, string $folderFsPath, string $folderWebPath) {

    $folderFsPath  = rtrim($folderFsPath, '/\\') . '/';
    $folderWebPath = rtrim($folderWebPath, '/\\') . '/';

    if (!is_dir($folderFsPath)) {
        return; // no folder = nothing to delete
    }

    // 1. Get all files currently on disk
    $filesOnDisk = glob($folderFsPath . "*");

    // 2. Find all <img src="">
    preg_match_all('/<img[^>]+src=["\']([^"\']+)["\']/i', $html, $matches);
    $htmlImagePaths = $matches[1] ?? [];

    // Normalize paths: keep only filenames belonging to this template folder
    $referencedFiles = [];

    foreach ($htmlImagePaths as $src) {
        if (strpos($src, $folderWebPath) !== false) {
            $filename = basename($src);
            $referencedFiles[] = $filename;
        }
    }

    // 3. Delete any physical file not referenced in the HTML
    foreach ($filesOnDisk as $filePath) {
        $filename = basename($filePath);

        if (!in_array($filename, $referencedFiles)) {
            unlink($filePath);
        }
    }
}

/**
 * Simple mysqli helper functions
 * - Prepared statements under the hood
 * - "Old style" INSERT/UPDATE SET feeling
 */

/**
 * Core executor: prepares, binds, executes.
 *
 * @throws Exception on error
 */
function dbExecute(mysqli $mysqli, string $sql, array $params = []): mysqli_stmt
{
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        throw new Exception('MySQLi prepare error: ' . $mysqli->error . ' | SQL: ' . $sql);
    }

    if (!empty($params)) {
        $types  = '';
        $values = [];

        foreach ($params as $param) {
            if (is_int($param)) {
                $types .= 'i';
            } elseif (is_float($param)) {
                $types .= 'd';
            } elseif (is_bool($param)) {
                $types .= 'i';
                $param  = $param ? 1 : 0;
            } elseif (is_null($param)) {
                $types .= 's';
                $param  = null;
            } else {
                $types .= 's';
            }
            $values[] = $param;
        }

        if (!$stmt->bind_param($types, ...$values)) {
            throw new Exception('MySQLi bind_param error: ' . $stmt->error . ' | SQL: ' . $sql);
        }
    }

    if (!$stmt->execute()) {
        throw new Exception('MySQLi execute error: ' . $stmt->error . ' | SQL: ' . $sql);
    }

    return $stmt;
}

/**
 * Fetch all rows as associative arrays.
 */
function dbFetchAll(mysqli $mysqli, string $sql, array $params = []): array
{
    $stmt   = dbExecute($mysqli, $sql, $params);
    $result = $stmt->get_result();
    if ($result === false) {
        return [];
    }
    return $result->fetch_all(MYSQLI_ASSOC);
}

/**
 * Fetch a single row (assoc) or null if none.
 */
function dbFetchOne(mysqli $mysqli, string $sql, array $params = []): ?array
{
    $stmt   = dbExecute($mysqli, $sql, $params);
    $result = $stmt->get_result();
    if ($result === false) {
        return null;
    }
    $row = $result->fetch_assoc();
    return $row !== null ? $row : null;
}

/**
 * Fetch a single scalar value (first column of first row) or null.
 */
function dbFetchValue(mysqli $mysqli, string $sql, array $params = [])
{
    $row = dbFetchOne($mysqli, $sql, $params);
    if ($row === null) {
        return null;
    }
    return reset($row);
}

/**
 * INSERT using "SET" style.
 * Example:
 *   $id = dbInsert($mysqli, 'clients', [
 *       'client_name' => $name,
 *       'client_type' => $type,
 *   ]);
 *
 * @return int insert_id
 *
 * @throws InvalidArgumentException
 * @throws Exception
 */
function dbInsert(mysqli $mysqli, string $table, array $data): int
{
    if (empty($data)) {
        throw new InvalidArgumentException('dbInsert called with empty $data');
    }

    $setParts = [];
    foreach ($data as $column => $_) {
        $setParts[] = "$column = ?";
    }

    $sql    = "INSERT INTO $table SET " . implode(', ', $setParts);
    $params = array_values($data);

    dbExecute($mysqli, $sql, $params);

    return $mysqli->insert_id;
}

function dbUpdate(
    mysqli $mysqli,
    string $table,
    array $data,
    $where,
    array $whereParams = []
): int {
    if (empty($data)) {
        throw new InvalidArgumentException('dbUpdate called with empty $data');
    }
    if (empty($where)) {
        throw new InvalidArgumentException('dbUpdate requires a WHERE clause');
    }

    $setParts = [];
    foreach ($data as $column => $_) {
        $setParts[] = "$column = ?";
    }

    if (is_array($where)) {
        $whereParts  = [];
        $whereParams = [];
        foreach ($where as $column => $value) {
            $whereParts[]  = "$column = ?";
            $whereParams[] = $value;
        }
        $whereSql = implode(' AND ', $whereParts);
    } else {
        $whereSql = $where;
    }

    $sql    = "UPDATE $table SET " . implode(', ', $setParts) . " WHERE $whereSql";
    $params = array_merge(array_values($data), $whereParams);

    $stmt = dbExecute($mysqli, $sql, $params);
    return $stmt->affected_rows;
}

/**
 * DELETE helper.
 *
 * WHERE can be:
 *   - array: ['client_id' => $id] (auto "client_id = ?")
 *   - string: 'client_id = ?' (use with $whereParams)
 *
 * @return int affected_rows
 *
 * @throws InvalidArgumentException
 * @throws Exception
 */
function dbDelete(
    mysqli $mysqli,
    string $table,
    $where,
    array $whereParams = []
): int {
    if (empty($where)) {
        throw new InvalidArgumentException('dbDelete requires a WHERE clause');
    }

    if (is_array($where)) {
        $whereParts  = [];
        $whereParams = [];
        foreach ($where as $column => $value) {
            $whereParts[]  = "$column = ?";
            $whereParams[] = $value;
        }
        $whereSql = implode(' AND ', $whereParts);
    } else {
        $whereSql = $where;
    }

    $sql  = "DELETE FROM $table WHERE $whereSql";
    $stmt = dbExecute($mysqli, $sql, $whereParams);
    return $stmt->affected_rows;
}

/**
 * Transaction helpers (optional sugar).
 */
function dbBegin(mysqli $mysqli): void
{
    $mysqli->begin_transaction();
}

function dbCommit(mysqli $mysqli): void
{
    $mysqli->commit();
}

function dbRollback(mysqli $mysqli): void
{
    $mysqli->rollback();
}

function formatDuration($time) {
    // expects "HH:MM:SS"
    [$h, $m, $s] = array_map('intval', explode(':', $time));

    $parts = [];

    if ($h > 0) $parts[] = $h . 'h';
    if ($m > 0) $parts[] = $m . 'm';

    // show seconds only if under 1 minute total OR if nothing else exists
    if ($h == 0 && $m == 0) {
        $parts[] = $s . 's';
    }

    return implode(' ', $parts);
}
