<?php
/**
 * HP LOGISTICS — endpoint sécurisé des formulaires (contact + devis)
 * Compatible hébergement mutualisé LWS (Apache + PHP 7.4+, sans dépendance externe).
 *
 *   GET  /api/forms.php?action=token   -> jeton signé (anti-robot : délai minimal)
 *   POST /api/forms.php  (JSON)        -> {type, token, lang, hp_website, fields:{...}}
 */
define('HP_FORMS', 1);
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');
error_reporting(E_ALL);
$cfg = require dirname(__FILE__) . '/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

/* ---------- Utilitaires ---------- */
function out($code, $arr) {
    http_response_code($code);
    echo json_encode($arr, JSON_UNESCAPED_UNICODE);
    exit;
}

function clen($s) {
    return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : preg_match_all('/./us', $s, $m);
}

$LANG = 'fr';
$MSG = array(
    'fr' => array(
        'method'   => 'Méthode non autorisée.',
        'origin'   => 'Requête refusée.',
        'format'   => 'Requête invalide.',
        'toolarge' => 'Requête trop volumineuse.',
        'token'    => 'Session de formulaire invalide. Rechargez la page puis réessayez.',
        'expired'  => 'Session de formulaire expirée. Rechargez la page puis réessayez.',
        'too_fast' => 'Veuillez patienter quelques secondes avant d\'envoyer le formulaire.',
        'rate'     => 'Trop de demandes. Réessayez dans quelques minutes ou appelez-nous.',
        'spam'     => 'Votre message a été refusé (liens ou contenu suspect).',
        'invalid'  => 'Veuillez corriger les champs signalés.',
        'server'   => 'Service momentanément indisponible. Contactez-nous par e-mail ou par téléphone.',
        'required' => 'Champ obligatoire.',
        'short'    => 'Trop court.',
        'long'     => 'Trop long.',
        'email'    => 'Adresse e-mail invalide.',
        'phone'    => 'Numéro de téléphone invalide.',
        'choice'   => 'Valeur non autorisée.',
    ),
    'en' => array(
        'method'   => 'Method not allowed.',
        'origin'   => 'Request refused.',
        'format'   => 'Invalid request.',
        'toolarge' => 'Request too large.',
        'token'    => 'Invalid form session. Please reload the page and try again.',
        'expired'  => 'Form session expired. Please reload the page and try again.',
        'too_fast' => 'Please wait a few seconds before submitting the form.',
        'rate'     => 'Too many requests. Please try again in a few minutes or call us.',
        'spam'     => 'Your message was rejected (links or suspicious content).',
        'invalid'  => 'Please correct the highlighted fields.',
        'server'   => 'Service temporarily unavailable. Please contact us by email or phone.',
        'required' => 'Required field.',
        'short'    => 'Too short.',
        'long'     => 'Too long.',
        'email'    => 'Invalid email address.',
        'phone'    => 'Invalid phone number.',
        'choice'   => 'Value not allowed.',
    ),
);
function m($k) { global $MSG, $LANG; return $MSG[$LANG][$k]; }

function ensure_dir($d) { if (!is_dir($d)) { @mkdir($d, 0700, true); } return is_dir($d) && is_writable($d); }

function get_secret($cfg) {
    if (!empty($cfg['secret']) && strlen($cfg['secret']) >= 20) { return $cfg['secret']; }
    $f = $cfg['data_dir'] . '/secret.key';
    if (ensure_dir($cfg['data_dir'])) {
        if (is_file($f)) { $s = trim((string)@file_get_contents($f)); if (strlen($s) >= 32) { return $s; } }
        $s = bin2hex(random_bytes(32));
        @file_put_contents($f, $s, LOCK_EX);
        @chmod($f, 0600);
        return $s;
    }
    // Dossier non inscriptible : secret dérivé de l'environnement (moins robuste mais fonctionnel)
    return hash('sha256', __FILE__ . (isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : ''));
}

function client_ip($cfg) {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    if (!empty($cfg['trust_proxy_headers']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $cand = trim($parts[0]);
        if (filter_var($cand, FILTER_VALIDATE_IP)) { $ip = $cand; }
    }
    return $ip;
}

function log_event($cfg, $event, $ipHash) {
    if (!ensure_dir($cfg['data_dir'])) { return; }
    $f = $cfg['data_dir'] . '/forms.log';
    if (is_file($f) && filesize($f) > 1048576) { @rename($f, $f . '.1.bak'); }
    @file_put_contents($f, date('c') . ' ' . $event . ' ' . substr($ipHash, 0, 10) . "\n", FILE_APPEND | LOCK_EX);
}

/* Limiteur : renvoie true si l'action est autorisée (et l'enregistre). */
function rl_hit($cfg, $key, $max, $window, $record = true) {
    $dir = $cfg['data_dir'] . '/rl';
    if (!ensure_dir($dir)) { return true; } // ne pas bloquer le site si le disque est inaccessible
    $fh = @fopen($dir . '/' . sha1($key) . '.json', 'c+');
    if (!$fh) { return true; }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $arr = $raw ? json_decode($raw, true) : array();
    if (!is_array($arr)) { $arr = array(); }
    $now = time();
    $arr = array_values(array_filter($arr, function ($t) use ($now, $window) { return ($now - (int)$t) < $window; }));
    $ok = count($arr) < $max;
    if ($ok && $record) { $arr[] = $now; }
    ftruncate($fh, 0); rewind($fh);
    fwrite($fh, json_encode($arr));
    flock($fh, LOCK_UN); fclose($fh);
    return $ok;
}

function rl_cleanup($cfg) {
    if (mt_rand(1, 50) !== 1) { return; }
    foreach ((array)@glob($cfg['data_dir'] . '/rl/*.json') as $f) {
        if (@filemtime($f) < time() - 172800) { @unlink($f); }
    }
}

/* ---------- Jeton ---------- */
function make_token($secret) {
    $ts = time(); $n = bin2hex(random_bytes(8));
    return $ts . '.' . $n . '.' . hash_hmac('sha256', $ts . '.' . $n, $secret);
}
/* Retourne 'ok' | 'token' | 'expired' | 'too_fast' */
function check_token($tok, $secret, $cfg) {
    if (!is_string($tok) || substr_count($tok, '.') !== 2) { return 'token'; }
    list($ts, $n, $sig) = explode('.', $tok);
    if (!ctype_digit($ts) || !preg_match('/^[a-f0-9]{16}$/', $n)) { return 'token'; }
    if (!hash_equals(hash_hmac('sha256', $ts . '.' . $n, $secret), $sig)) { return 'token'; }
    $age = time() - (int)$ts;
    if ($age > $cfg['max_token_age']) { return 'expired'; }
    if ($age < $cfg['min_fill_seconds']) { return 'too_fast'; }
    return 'ok';
}

/* ---------- Nettoyage / validation ---------- */
function clean($v, $multiline) {
    if (!is_string($v)) { return ''; }
    if (!preg_match('//u', $v)) { return ''; }               // UTF-8 invalide
    $v = strip_tags(str_replace("\0", '', $v));
    $v = str_replace(array("\r\n", "\r"), "\n", $v);
    if ($multiline) {
        $v = preg_replace('/[^\P{C}\n]+/u', '', $v);
        $v = preg_replace("/[ \t]+/u", ' ', $v);
        $v = preg_replace("/\n{3,}/", "\n\n", $v);
    } else {
        $v = preg_replace('/\s+/u', ' ', $v);
        $v = preg_replace('/\p{C}+/u', '', $v);
    }
    return trim((string)$v);
}

function check_field(&$errs, $name, $val, $min, $max, $required) {
    $l = clen($val);
    if ($val === '') { if ($required) { $errs[$name] = m('required'); } return; }
    if ($l < $min) { $errs[$name] = m('short'); }
    elseif ($l > $max) { $errs[$name] = m('long'); }
}

function validate($type, $in, &$clean) {
    $errs = array();
    $g = function ($k) use ($in) { return isset($in[$k]) ? $in[$k] : ''; };
    $clean['name']  = clean($g('name'), false);
    $clean['email'] = clean($g('email'), false);
    $clean['phone'] = clean($g('phone'), false);
    check_field($errs, 'name', $clean['name'], 2, 100, true);
    if ($clean['email'] === '') { $errs['email'] = m('required'); }
    elseif (strlen($clean['email']) > 254 || !filter_var($clean['email'], FILTER_VALIDATE_EMAIL)
            || preg_match('/[\r\n,;<>]/', $clean['email'])) { $errs['email'] = m('email'); }
    if ($clean['phone'] !== '') {
        $digits = preg_match_all('/\d/', $clean['phone']);
        if (!preg_match('/^[0-9+().\s-]{6,30}$/', $clean['phone']) || $digits < 6) { $errs['phone'] = m('phone'); }
    }
    if ($type === 'contact') {
        $clean['subject'] = clean($g('subject'), false);
        $clean['message'] = clean($g('message'), true);
        check_field($errs, 'subject', $clean['subject'], 3, 150, true);
        check_field($errs, 'message', $clean['message'], 10, 5000, true);
    } else {
        $clean['goods_type']     = clean($g('goods_type'), false);
        $clean['weight']         = clean($g('weight'), false);
        $clean['origin']         = clean($g('origin'), false);
        $clean['destination']    = clean($g('destination'), false);
        $clean['transport_mode'] = clean($g('transport_mode'), false);
        $clean['details']        = clean($g('details'), true);
        check_field($errs, 'goods_type', $clean['goods_type'], 2, 200, true);
        check_field($errs, 'weight', $clean['weight'], 1, 50, false);
        check_field($errs, 'origin', $clean['origin'], 2, 200, true);
        check_field($errs, 'destination', $clean['destination'], 2, 200, true);
        check_field($errs, 'details', $clean['details'], 1, 2000, false);
        if (!in_array($clean['transport_mode'], array('maritime', 'aerien', 'routier', 'ferroviaire', 'multimodal'), true)) {
            $errs['transport_mode'] = m('choice');
        }
    }
    return $errs;
}

/* ---------- Livraison ---------- */
function deliver_db($cfg, $type, $c) {
    $key = !empty($cfg['supabase_service_key']) ? $cfg['supabase_service_key'] : $cfg['supabase_key'];
    if (empty($cfg['supabase_url']) || empty($key)) { return false; }
    if ($type === 'contact') {
        $table = 'contact_messages';
        $row = array('name' => $c['name'], 'email' => $c['email'], 'phone' => $c['phone'] !== '' ? $c['phone'] : null,
                     'subject' => $c['subject'], 'message' => $c['message']);
    } else {
        $table = 'quote_requests';
        $row = array('name' => $c['name'], 'email' => $c['email'], 'phone' => $c['phone'] !== '' ? $c['phone'] : null,
                     'goods_type' => $c['goods_type'], 'weight' => $c['weight'] !== '' ? $c['weight'] : null,
                     'origin' => $c['origin'], 'destination' => $c['destination'],
                     'transport_mode' => $c['transport_mode'], 'details' => $c['details'] !== '' ? $c['details'] : null);
    }
    $headers = array('Content-Type: application/json', 'apikey: ' . $key, 'Prefer: return=minimal');
    if (strpos($key, 'eyJ') === 0) { $headers[] = 'Authorization: Bearer ' . $key; } // clés JWT historiques uniquement
    $url = rtrim($cfg['supabase_url'], '/') . '/rest/v1/' . $table;
    $body = json_encode($row, JSON_UNESCAPED_UNICODE);
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2));
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code >= 200 && $code < 300;
    }
    $ctx = stream_context_create(array('http' => array('method' => 'POST', 'header' => implode("\r\n", $headers),
        'content' => $body, 'timeout' => 8, 'ignore_errors' => true)));
    @file_get_contents($url, false, $ctx);
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $mm)) {
        return (int)$mm[1] >= 200 && (int)$mm[1] < 300;
    }
    return false;
}

function deliver_mail($cfg, $type, $c) {
    if (empty($cfg['mail_enabled']) || !function_exists('mail')) { return false; }
    $label = $type === 'contact' ? 'Contact' : 'Demande de devis';
    $subject = '=?UTF-8?B?' . base64_encode('[HP LOGISTICS] ' . $label . ' - ' . $c['name']) . '?=';
    $lines = array();
    foreach ($c as $k => $v) { if ($v !== '') { $lines[] = $k . ' : ' . $v; } }
    $body = implode("\n", $lines) . "\n\n-- Envoyé depuis le formulaire du site (" . date('Y-m-d H:i:s') . ")\n";
    $headers = 'From: HP LOGISTICS <' . $cfg['mail_from'] . ">\r\n"
             . 'Reply-To: ' . $c['email'] . "\r\n"
             . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
    return @mail($cfg['notify_to'], $subject, $body, $headers, '-f' . $cfg['mail_from']);
}

function deliver_outbox($cfg, $type, $c) {
    if (empty($cfg['outbox_enabled'])) { return false; }
    $dir = $cfg['data_dir'] . '/outbox';
    if (!ensure_dir($dir)) { return false; }
    $f = $dir . '/' . date('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.json';
    $ok = @file_put_contents($f, json_encode(array('type' => $type, 'received' => date('c'), 'data' => $c), JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
    if ($ok) { @chmod($f, 0600); }
    return (bool)$ok;
}

/* ---------- Contrôle d'origine ---------- */
function origin_ok($cfg) {
    $src = !empty($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '');
    if ($src === '') { return false; }
    $host = parse_url($src, PHP_URL_HOST);
    return $host && in_array(strtolower($host), $cfg['allowed_hosts'], true);
}

/* ================= Routage ================= */
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$secret = get_secret($cfg);

if ($method === 'GET') {
    if (isset($_GET['action']) && $_GET['action'] === 'token' && origin_ok($cfg)) {
        out(200, array('ok' => true, 'token' => make_token($secret)));
    }
    out(origin_ok($cfg) ? 400 : 403, array('ok' => false, 'code' => 'format', 'message' => m('format')));
}
if ($method !== 'POST') { header('Allow: GET, POST'); out(405, array('ok' => false, 'code' => 'method', 'message' => m('method'))); }

if (!origin_ok($cfg)) { out(403, array('ok' => false, 'code' => 'origin', 'message' => m('origin'))); }
$ct = isset($_SERVER['CONTENT_TYPE']) ? strtolower($_SERVER['CONTENT_TYPE']) : '';
if (strpos($ct, 'application/json') !== 0) { out(415, array('ok' => false, 'code' => 'format', 'message' => m('format'))); }
$raw = file_get_contents('php://input', false, null, 0, 20001);
if ($raw === false || strlen($raw) > 20000) { out(413, array('ok' => false, 'code' => 'toolarge', 'message' => m('toolarge'))); }
$data = json_decode($raw, true);
if (!is_array($data) || !isset($data['fields']) || !is_array($data['fields'])) { out(400, array('ok' => false, 'code' => 'format', 'message' => m('format'))); }
if (isset($data['lang']) && $data['lang'] === 'en') { $LANG = 'en'; }
$type = isset($data['type']) ? $data['type'] : '';
if ($type !== 'contact' && $type !== 'quote') { out(400, array('ok' => false, 'code' => 'format', 'message' => m('format'))); }

$ipHash = hash_hmac('sha256', client_ip($cfg), $secret);
rl_cleanup($cfg);

// 1. Plafond de tentatives (toutes requêtes POST)
if (!rl_hit($cfg, 'att:' . $ipHash, $cfg['rate_attempts'][0], $cfg['rate_attempts'][1])) {
    log_event($cfg, 'rate_attempts', $ipHash);
    out(429, array('ok' => false, 'code' => 'rate', 'message' => m('rate')));
}

// 2. Jeton signé (délai minimal + expiration)
$tk = check_token(isset($data['token']) ? $data['token'] : '', $secret, $cfg);
if ($tk !== 'ok') {
    log_event($cfg, 'token_' . $tk, $ipHash);
    out($tk === 'too_fast' ? 429 : 400, array('ok' => false, 'code' => $tk, 'message' => m($tk)));
}

// 3. Pot de miel : un robot remplit le champ caché -> succès simulé, rien n'est enregistré
if (isset($data['hp_website']) && $data['hp_website'] !== '') {
    log_event($cfg, 'honeypot', $ipHash);
    out(200, array('ok' => true));
}

// 4. Validation
$c = array();
$errs = validate($type, $data['fields'], $c);
if ($errs) { out(422, array('ok' => false, 'code' => 'invalid', 'message' => m('invalid'), 'fields' => $errs)); }

// 5. Contenu suspect : trop de liens
$all = implode(' ', $c);
if (preg_match_all('~(?:https?://|www\.)~i', $all) > $cfg['max_links'] || preg_match('~\[/?url|<a\s~i', $all)) {
    log_event($cfg, 'spam_links', $ipHash);
    out(422, array('ok' => false, 'code' => 'spam', 'message' => m('spam')));
}

// 6. Doublon (double clic / renvoi) : succès sans nouvel enregistrement
if (!rl_hit($cfg, 'dup:' . hash('sha256', $type . $c['email'] . json_encode($c)), 1, 3600)) {
    out(200, array('ok' => true));
}

// 7. Plafonds d'envois acceptés
if (!rl_hit($cfg, 'send10:' . $ipHash, $cfg['rate_send_10min'][0], $cfg['rate_send_10min'][1])
    || !rl_hit($cfg, 'sendday:' . $ipHash, $cfg['rate_send_day'][0], $cfg['rate_send_day'][1])
    || !rl_hit($cfg, 'global:' . date('Ymd'), $cfg['rate_global_day'][0], $cfg['rate_global_day'][1])) {
    log_event($cfg, 'rate_send', $ipHash);
    out(429, array('ok' => false, 'code' => 'rate', 'message' => m('rate')));
}

// 8. Livraison : base + e-mail + copie de secours. Succès si au moins un canal a fonctionné.
$db = deliver_db($cfg, $type, $c);
$ml = deliver_mail($cfg, $type, $c);
$ob = (!$db && !$ml) ? deliver_outbox($cfg, $type, $c) : false;
log_event($cfg, 'sent ' . $type . ' db=' . (int)$db . ' mail=' . (int)$ml . ' outbox=' . (int)$ob, $ipHash);
if ($db || $ml || $ob) { out(200, array('ok' => true)); }
out(502, array('ok' => false, 'code' => 'server', 'message' => m('server')));
