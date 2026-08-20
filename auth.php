<?php
/**
 * LAN Stream — Auth Gate  (auth.php)
 * ─────────────────────────────────────────────────────────────────────────────
 * ENTRY POINT for all devices. stream.php redirects here when the session is
 * absent or expired. A one-time PIN is generated and displayed in the server
 * terminal. The person at the PC reads it out; the remote user types it in.
 * On success a 24-hour session is created and the browser lands on stream.php.
 */

// ─── SHARED CONFIGURATION ─────────────────────────────────────────────────────
define('SESSION_DIR',      __DIR__ . '/data/sess');
define('SESSION_REGISTRY', __DIR__ . '/data/sessions.json');
define('PIN_QUEUE_FILE',   __DIR__ . '/data/pin_queue.json');
define('LOG_FILE',         __DIR__ . '/logs/stream.log');
define('SESSION_LIFETIME', 86400);   // 24 h session after successful auth
define('PIN_LIFETIME',     300);     // seconds a generated PIN stays valid
define('PIN_DIGITS',       6);       // numeric PIN length
define('MASTER_PIN',       '');      // optional always-valid admin PIN ('' = off)
define('STREAM_URL',       'stream.php');

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function log_event(string $msg): void {
    $dir = dirname(LOG_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    @file_put_contents(LOG_FILE,
        '[' . date('Y-m-d H:i:s') . '] [' . ($_SERVER['REMOTE_ADDR'] ?? 'cli') . '] ' . $msg . PHP_EOL,
        FILE_APPEND | LOCK_EX);
}

function json_out(mixed $data): never {
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function json_error(int $code, string $msg): never {
    http_response_code($code);
    json_out(['error' => $msg]);
}

// ─── SESSION REGISTRY ─────────────────────────────────────────────────────────
// Shared with stream.php — both use the same lock-protected JSON file.

function registry_load(): array {
    if (!file_exists(SESSION_REGISTRY)) return [];
    $fp = @fopen(SESSION_REGISTRY, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $data = json_decode(stream_get_contents($fp), true) ?? [];
    flock($fp, LOCK_UN);
    fclose($fp);
    return $data;
}

function registry_save(array $data): void {
    $dir = dirname(SESSION_REGISTRY);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $fp = @fopen(SESSION_REGISTRY, 'c');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    flock($fp, LOCK_UN);
    fclose($fp);
}

function registry_add(string $sid, string $ip, string $ua): void {
    $s = registry_load();
    $s[$sid] = [
        'sid'           => $sid,
        'ip'            => $ip,
        'ua'            => $ua,
        'login_time'    => time(),
        'last_activity' => time(),
        'expires'       => time() + SESSION_LIFETIME,
    ];
    registry_save($s);
}

function registry_remove(string $sid): void {
    $s = registry_load();
    unset($s[$sid]);
    registry_save($s);
}

// ─── PIN QUEUE ────────────────────────────────────────────────────────────────
function pin_queue_load(): array {
    if (!file_exists(PIN_QUEUE_FILE)) return [];
    $fp = @fopen(PIN_QUEUE_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $data = json_decode(stream_get_contents($fp), true) ?? [];
    flock($fp, LOCK_UN);
    fclose($fp);
    return $data;
}

function pin_queue_save(array $data): void {
    $dir = dirname(PIN_QUEUE_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $fp = @fopen(PIN_QUEUE_FILE, 'c');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
}

function pin_request(string $ip): array {
    $queue = pin_queue_load();
    $now   = time();
    // Reuse existing valid PIN for this IP so the terminal doesn't spam
    if (isset($queue[$ip])
        && $queue[$ip]['expires_at'] > $now
        && !($queue[$ip]['used'] ?? false)) {
        return $queue[$ip];
    }
    // Generate fresh cryptographically random PIN
    $pin   = str_pad((string)random_int(0, (int)(10 ** PIN_DIGITS) - 1), PIN_DIGITS, '0', STR_PAD_LEFT);
    $entry = ['pin' => $pin, 'ip' => $ip, 'generated_at' => $now, 'expires_at' => $now + PIN_LIFETIME, 'used' => false];
    $queue[$ip] = $entry;
    pin_queue_save($queue);
    pin_print_terminal($ip, $pin, $now + PIN_LIFETIME);
    log_event("PIN GENERATED | ip=$ip | pin=$pin");
    return $entry;
}

function pin_validate(string $ip, string $pin): bool {
    if (MASTER_PIN !== '' && hash_equals(MASTER_PIN, $pin)) return true;
    $queue = pin_queue_load();
    if (!isset($queue[$ip])) return false;
    $e = $queue[$ip];
    if ($e['used'] ?? false)       return false;
    if ($e['expires_at'] <= time()) return false;
    return hash_equals($e['pin'], $pin);
}

function pin_consume(string $ip): void {
    $queue = pin_queue_load();
    if (isset($queue[$ip])) { $queue[$ip]['used'] = true; pin_queue_save($queue); }
}

function pin_is_expired(string $ip): bool {
    $queue = pin_queue_load();
    if (!isset($queue[$ip])) return true;
    return $queue[$ip]['expires_at'] <= time();
}

function pin_print_terminal(string $ip, string $pin, int $expires_at): void {
    $time    = date('Y-m-d H:i:s');
    $expTime = date('H:i:s', $expires_at);
    $sep     = str_repeat('-', 46);
    $msg = PHP_EOL
        . "  +{$sep}+" . PHP_EOL
        . "  |   >> NEW CONNECTION REQUEST" . str_repeat(' ', 16) . "|" . PHP_EOL
        . "  +{$sep}+" . PHP_EOL
        . sprintf("  |  Time    : %-33s|" . PHP_EOL, $time)
        . sprintf("  |  Device  : %-33s|" . PHP_EOL, $ip)
        . sprintf("  |  PIN     : %-33s|" . PHP_EOL, $pin)
        . sprintf("  |  Expires : %-33s|" . PHP_EOL, "{$expTime}  (" . PIN_LIFETIME . "s)")
        . "  +{$sep}+" . PHP_EOL
        . "  >> Tell this PIN to the person connecting!" . PHP_EOL . PHP_EOL;

    $stderr = @fopen('php://stderr', 'w');
    if ($stderr) {
        @fwrite($stderr, $msg);
        @fclose($stderr);
    }
}

/**
 * Print simple formatted status info directly to stderr.
 */
function print_system_status(string $title, string $msg, string $next = ''): void {
    $time = date('Y-m-d H:i:s');
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Bold / Reset characters for cleaner logs
    $bold  = "\033[1m";
    $reset = "\033[0m";
    
    $clean_msg = PHP_EOL
        . "  [{$time}] [{$ip}] {$bold}=== {$title} ==={$reset}" . PHP_EOL
        . "  Reason : {$msg}" . PHP_EOL;
    if ($next) {
        $clean_msg .= "  Next   : {$next}" . PHP_EOL;
    }
    $clean_msg .= PHP_EOL;

    $stderr = @fopen('php://stderr', 'w');
    if ($stderr) {
        @fwrite($stderr, $clean_msg);
        @fclose($stderr);
    }
}

// ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
function is_authorized(): bool {
    return ($_SESSION['authorized'] ?? false) === true
        && ($_SESSION['expires'] ?? 0) > time();
}

function session_authorize(string $ip, string $ua): void {
    session_regenerate_id(true);
    $_SESSION['authorized'] = true;
    $_SESSION['expires']    = time() + SESSION_LIFETIME;
    $_SESSION['ip']         = $ip;
    $_SESSION['ua']         = $ua;
    $_SESSION['login_time'] = time();
    $sid = session_id();
    session_write_close();
    registry_add($sid, $ip, $ua);
}

function session_deauthorize(): void {
    $sid = session_id();
    $_SESSION = [];
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 86400,
        $p['path'], $p['domain'] ?? '', $p['secure'] ?? false, $p['httponly'] ?? true);
    session_destroy();
    registry_remove($sid);
}

// ─── SESSION BOOTSTRAP ────────────────────────────────────────────────────────
if (!is_dir(SESSION_DIR)) @mkdir(SESSION_DIR, 0700, true);
ini_set('session.gc_maxlifetime', (string)SESSION_LIFETIME);
ini_set('session.use_strict_mode', '1');
session_set_cookie_params(['lifetime' => SESSION_LIFETIME, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
session_save_path(SESSION_DIR);
session_start();

// Already logged in? Go straight to the streamer.
if (is_authorized()) {
    session_write_close();
    header('Location: ' . STREAM_URL);
    exit;
}

session_write_close(); // release lock for all public actions below

// ─── ROUTER ───────────────────────────────────────────────────────────────────
$action = $_GET['action'] ?? 'ui';
match ($action) {
    'request_pin' => action_request_pin(),
    'auth'        => action_auth(),
    'check_auth'  => action_check_auth(),
    'logout'      => action_logout(),
    'ui'          => action_ui(),
    default       => json_error(404, 'Unknown action'),
};

// ─── ACTION: REQUEST PIN ──────────────────────────────────────────────────────
function action_request_pin(): void {
    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $entry = pin_request($ip);
    $now   = time();
    json_out(['ok' => true, 'expires_in' => max(0, $entry['expires_at'] - $now), 'expires_at' => $entry['expires_at']]);
}

// ─── ACTION: AUTH ─────────────────────────────────────────────────────────────
function action_auth(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_error(405, 'POST required');
    $body = json_decode(file_get_contents('php://input'), true) ?? [];
    $pin  = trim((string)($body['pin'] ?? ''));
    $ip   = $_SERVER['REMOTE_ADDR']     ?? 'unknown';
    $ua   = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    session_start(); // re-open for writing

    if ($pin !== '' && pin_validate($ip, $pin)) {
        pin_consume($ip);
        session_authorize($ip, $ua);
        log_event("AUTH OK | ip=$ip");
        print_system_status("AUTH OK", "Device successfully authenticated.", "Redirecting to stream.php.");
        json_out(['ok' => true, 'redirect' => STREAM_URL]);
    } else {
        session_write_close();
        usleep(500_000);
        log_event("AUTH FAIL | ip=$ip");
        $expired = pin_is_expired($ip);
        $reason  = $expired ? 'PIN expired' : 'Invalid PIN';
        $next    = $expired ? 'Generating a new PIN automatically.' : 'User must enter the correct PIN.';
        print_system_status("AUTH FAIL", "Authentication failed. Reason: $reason.", $next);
        http_response_code(401);
        json_out(['ok' => false, 'error' => $reason, 'expired' => $expired]);
    }
}

// ─── ACTION: CHECK AUTH ───────────────────────────────────────────────────────
function action_check_auth(): void {
    session_start();
    $auth = is_authorized();
    session_write_close();
    json_out(['authorized' => $auth, 'redirect' => $auth ? STREAM_URL : null]);
}

// ─── ACTION: LOGOUT ───────────────────────────────────────────────────────────
function action_logout(): void {
    session_start();
    session_deauthorize();
    print_system_status("LOGOUT", "Device logged out manually.", "Session cleared.");
    json_out(['ok' => true]);
}

// ─── ACTION: UI ───────────────────────────────────────────────────────────────
function action_ui(): void {
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAN Stream — Connect</title>
<meta name="description" content="LAN Stream secure access portal. Enter your one-time PIN to connect.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #080810;
  --surf:    #0f0f18;
  --surf2:   #13131e;
  --border:  #1c1c2a;
  --border2: #252535;
  --accent:  #00e5ff;
  --accent2: #7b2fff;
  --text:    #e2e2f0;
  --muted:   #50506a;
  --muted2:  #3a3a52;
  --green:   #00ffaa;
  --yellow:  #ffd700;
  --red:     #ff4466;
  --r:       6px;
  --trans:   .15s cubic-bezier(.4,0,.2,1);
}

html, body {
  height: 100%; min-height: 100dvh;
  background: var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  overflow: hidden;
}

/* ── ANIMATED GRID BACKGROUND ──────────────────────────────────────────────── */
.bg-grid {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(0,229,255,.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,.03) 1px, transparent 1px);
  background-size: 48px 48px;
  animation: gridDrift 30s linear infinite;
}
@keyframes gridDrift { to { background-position: 48px 48px; } }

/* animated glow orbs */
.orb {
  position: fixed; border-radius: 50%; filter: blur(80px);
  animation: orbFloat 12s ease-in-out infinite alternate;
  pointer-events: none; z-index: 0;
}
.orb-1 { width: 400px; height: 400px; top: -120px; left: -80px;
  background: radial-gradient(circle, rgba(0,229,255,.08) 0%, transparent 70%); animation-delay: 0s; }
.orb-2 { width: 350px; height: 350px; bottom: -100px; right: -60px;
  background: radial-gradient(circle, rgba(123,47,255,.09) 0%, transparent 70%); animation-delay: -5s; }
.orb-3 { width: 250px; height: 250px; top: 40%; left: 50%;
  background: radial-gradient(circle, rgba(0,255,170,.05) 0%, transparent 70%); animation-delay: -9s; }
@keyframes orbFloat { 0%{transform:translate(0,0) scale(1)} 100%{transform:translate(30px,20px) scale(1.08)} }

/* scanline overlay */
body::after {
  content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,.06) 2px, rgba(0,0,0,.06) 4px);
}

/* ── PAGE LAYOUT ───────────────────────────────────────────────────────────── */
.page {
  position: relative; z-index: 1;
  min-height: 100dvh;
  display: grid;
  grid-template-columns: 1fr 420px 1fr;
  grid-template-rows: 1fr auto 1fr;
  align-items: center; justify-items: center;
  padding: 24px;
}

/* ── TOP STATUS BAR ────────────────────────────────────────────────────────── */
.status-bar {
  position: fixed; top: 0; left: 0; right: 0; z-index: 10;
  height: 36px;
  display: flex; align-items: center; gap: 14px;
  padding: 0 18px;
  background: rgba(8,8,16,.9);
  border-bottom: 1px solid var(--border);
  font-size: 9px; letter-spacing: 1px; color: var(--muted2);
}
.sb-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); animation: blink 2s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
.sb-sep { color: var(--border2); }
.sb-right { margin-left: auto; display: flex; gap: 10px; align-items: center; }

/* ── AUTH CARD ─────────────────────────────────────────────────────────────── */
.auth-card {
  grid-column: 2; grid-row: 2;
  width: 100%; max-width: 420px;
  background: var(--surf);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 36px 32px 28px;
  box-shadow:
    0 0 0 1px rgba(0,229,255,.04),
    0 0 80px rgba(0,229,255,.04),
    0 40px 80px rgba(0,0,0,.7);
  position: relative; overflow: hidden;
  animation: cardIn .5s cubic-bezier(.2,.9,.4,1) both;
}
@keyframes cardIn { from{opacity:0;transform:scale(.94) translateY(20px)} to{opacity:1;transform:scale(1) translateY(0)} }

/* top accent line */
.auth-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent 5%, var(--accent) 40%, var(--accent2) 60%, transparent 95%);
  opacity: .6;
}

/* corner accents */
.auth-card::after {
  content: ''; position: absolute; bottom: 0; right: 0;
  width: 80px; height: 80px;
  border-bottom: 1px solid rgba(123,47,255,.2);
  border-right: 1px solid rgba(123,47,255,.2);
  border-radius: 0 0 12px 0;
  pointer-events: none;
}

/* shake animation */
@keyframes shake {
  0%,100%{transform:translateX(0)} 15%{transform:translateX(-10px)} 35%{transform:translateX(9px)}
  55%{transform:translateX(-6px)} 75%{transform:translateX(4px)} 90%{transform:translateX(-2px)}
}
.auth-card.shaking { animation: shake .5s cubic-bezier(.36,.07,.19,.97); }

/* ── LOGO ──────────────────────────────────────────────────────────────────── */
.logo-row {
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 24px;
}
.logo-icon {
  width: 44px; height: 44px; flex-shrink: 0;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 10px; display: grid; place-items: center;
  font-size: 20px; box-shadow: 0 0 28px rgba(0,229,255,.25);
}
.logo-text { font-family: 'Syne', sans-serif; font-size: 26px; font-weight: 800; }
.logo-text em { color: var(--accent); font-style: normal; }
.logo-sub {
  font-size: 9px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--muted); margin-top: 2px;
}

/* ── SYSINFO STRIP ─────────────────────────────────────────────────────────── */
.sysinfo {
  display: flex; justify-content: space-between; align-items: center;
  background: rgba(255,255,255,.02); border: 1px solid var(--border);
  border-radius: 4px; padding: 8px 12px; margin-bottom: 28px;
  font-size: 9px; color: var(--muted2); letter-spacing: .5px;
}
.si-label { color: var(--muted); }

/* ── PHASE SYSTEM ──────────────────────────────────────────────────────────── */
.phase { display: none; }
.phase.active { display: block; }

/* Phase A: requesting */
.requesting-wrap {
  text-align: center; padding: 8px 0 6px;
}
.req-spinner {
  width: 42px; height: 42px; margin: 0 auto 16px;
  border: 3px solid var(--border2); border-top-color: var(--accent);
  border-radius: 50%; animation: spin .9s linear infinite;
}
@keyframes spin { to{transform:rotate(360deg)} }
.req-title {
  font-size: 12px; font-weight: 700; letter-spacing: 1.5px;
  text-transform: uppercase; color: var(--text); margin-bottom: 8px;
}
.req-sub { font-size: 10px; color: var(--muted); line-height: 1.8; }

/* Phase B: PIN input */
.pin-status {
  display: flex; align-items: center; gap: 10px;
  background: rgba(0,255,170,.05); border: 1px solid rgba(0,255,170,.15);
  border-radius: 5px; padding: 9px 14px; margin-bottom: 20px;
}
.pin-status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--green); box-shadow: 0 0 8px var(--green);
  animation: blink 1.4s infinite; flex-shrink: 0;
}
.pin-status-text { font-size: 10px; color: var(--green); flex: 1; }
.pin-countdown {
  font-size: 14px; font-weight: 700; color: var(--accent);
  font-variant-numeric: tabular-nums; flex-shrink: 0;
}
.pin-countdown.warn { color: var(--yellow); }
.pin-countdown.crit { color: var(--red);    }

.field-label {
  font-size: 9px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; color: var(--muted); margin-bottom: 8px;
}
.pin-wrap { position: relative; margin-bottom: 12px; }
.pin-input {
  width: 100%; padding: 14px 46px 14px 16px;
  background: var(--bg); border: 1px solid var(--border2);
  border-radius: var(--r); color: var(--accent);
  font-family: inherit; font-size: 22px; letter-spacing: 10px;
  outline: none; caret-color: var(--accent);
  transition: border-color var(--trans), box-shadow var(--trans);
}
.pin-input::placeholder { color: var(--muted2); letter-spacing: 3px; font-size: 13px; }
.pin-input:focus { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent), 0 0 28px rgba(0,229,255,.08); }
.pin-input.error { border-color: var(--red) !important; box-shadow: 0 0 0 1px var(--red); }

.eye-btn {
  position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
  background: none; border: none; color: var(--muted);
  cursor: pointer; font-size: 15px; padding: 4px;
  transition: color var(--trans);
}
.eye-btn:hover { color: var(--accent); }

.field-error {
  min-height: 18px; margin-bottom: 14px;
  font-size: 10px; color: var(--red);
}

.connect-btn {
  width: 100%; padding: 15px;
  background: linear-gradient(135deg, var(--accent) 0%, #00b4d8 100%);
  border: none; border-radius: var(--r);
  color: #000; font-family: inherit;
  font-weight: 700; font-size: 13px; letter-spacing: 3px;
  cursor: pointer; transition: all .2s;
}
.connect-btn:hover { box-shadow: 0 0 36px rgba(0,229,255,.4), 0 4px 20px rgba(0,0,0,.5); transform: translateY(-1px); }
.connect-btn:active { transform: translateY(0); }
.connect-btn:disabled { opacity: .4; cursor: not-allowed; transform: none; box-shadow: none; }

@keyframes spin-sm { to{transform:rotate(360deg)} }
.btn-spin {
  display: inline-block; width: 11px; height: 11px;
  border: 2px solid rgba(0,0,0,.25); border-top-color: #000;
  border-radius: 50%; animation: spin-sm .5s linear infinite;
  vertical-align: middle; margin-right: 6px;
}

/* ── FOOTER ────────────────────────────────────────────────────────────────── */
.card-footer {
  margin-top: 18px; text-align: center;
  font-size: 9px; color: var(--muted2); letter-spacing: .5px; line-height: 2;
}

/* ── BOTTOM BAR ────────────────────────────────────────────────────────────── */
.bottom-bar {
  position: fixed; bottom: 0; left: 0; right: 0;
  height: 32px; display: flex; align-items: center; justify-content: center;
  gap: 18px; font-size: 8px; letter-spacing: 1px; color: var(--muted2);
  background: rgba(8,8,16,.8); border-top: 1px solid var(--border);
}
.bottom-bar span { color: var(--muted); }

/* ── RESPONSIVE ────────────────────────────────────────────────────────────── */
@media (max-width: 520px) {
  .page { grid-template-columns: 1fr; padding: 56px 16px 48px; }
  .auth-card { max-width: 100%; padding: 28px 20px 22px; }
}
</style>
</head>
<body>

<!-- Background layers -->
<div class="bg-grid"></div>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>

<!-- Status bar -->
<div class="status-bar">
  <div class="sb-dot"></div>
  <span>LAN STREAM</span>
  <span class="sb-sep">|</span>
  <span id="sb-host">—</span>
  <div class="sb-right">
    <span id="sb-time">—</span>
  </div>
</div>

<!-- Auth card -->
<div class="page">
  <div class="auth-card" id="auth-card">

    <!-- Logo -->
    <div class="logo-row">
      <div class="logo-icon">⚡</div>
      <div>
        <div class="logo-text">LAN<em>Stream</em></div>
        <div class="logo-sub">Secure Access Portal</div>
      </div>
    </div>

    <!-- Server info -->
    <div class="sysinfo">
      <span><span class="si-label">HOST</span> <span id="si-host">loading…</span></span>
      <span><span class="si-label">SESSION</span> 24 h</span>
      <span><span class="si-label">PIN</span> <?= PIN_LIFETIME ?>s window</span>
    </div>

    <!-- Phase A: requesting PIN -->
    <div class="phase active" id="phase-requesting">
      <div class="requesting-wrap">
        <div class="req-spinner"></div>
        <div class="req-title" id="req-title">Requesting Access PIN</div>
        <div class="req-sub" id="req-sub">
          Generating a one-time PIN…<br>
          <span style="color:var(--muted2)">Check the server terminal window</span>
        </div>
      </div>
    </div>

    <!-- Phase B: PIN input -->
    <div class="phase" id="phase-waiting">
      <div class="pin-status">
        <div class="pin-status-dot"></div>
        <span class="pin-status-text">PIN ready — check the server terminal</span>
        <span class="pin-countdown" id="pin-countdown">5:00</span>
      </div>

      <div class="field-label">Enter the PIN shown in terminal</div>
      <div class="pin-wrap">
        <input type="password" id="pin-input" class="pin-input"
               autocomplete="off" placeholder="• • • • • •"
               inputmode="numeric" maxlength="20">
        <button class="eye-btn" id="eye-btn" onclick="toggleEye()" title="Show/hide">👁</button>
      </div>
      <div class="field-error" id="pin-error"></div>
      <button class="connect-btn" id="connect-btn" onclick="submitPin()">
        <span id="btn-label">CONNECT</span>
      </button>
    </div>

    <div class="card-footer">
      PIN refreshes automatically &middot; Sessions persist for 24 hours<br>
      Powered by <strong>LAN Stream v2</strong>
    </div>
  </div>
</div>

<!-- Bottom bar -->
<div class="bottom-bar">
  <span>WORKERS</span> PHP_CLI_SERVER_WORKERS
  <span>PROTOCOL</span> HTTP/1.1
  <span>STREAM</span> Byte-Range
</div>

<script>
const PIN_LIFETIME = <?= PIN_LIFETIME ?>;

let pinExpiresAt = 0;
let pinTimer     = null;

// ── INIT ──────────────────────────────────────────────────────────────────────
const host = window.location.hostname + ':' + (window.location.port || '80');
document.getElementById('sb-host').textContent = host;
document.getElementById('si-host').textContent = host;

setInterval(() => {
  document.getElementById('sb-time').textContent = new Date().toLocaleTimeString();
}, 1000);
document.getElementById('sb-time').textContent = new Date().toLocaleTimeString();

document.getElementById('pin-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); submitPin(); }
  document.getElementById('pin-input').classList.remove('error');
  document.getElementById('pin-error').textContent = '';
});

// Boot: check if already authorised, then request PIN
checkAuth();

// ── AUTH CHECK ────────────────────────────────────────────────────────────────
async function checkAuth() {
  try {
    const r    = await fetch('auth.php?action=check_auth');
    const data = await r.json();
    if (data.authorized) {
      window.location.href = '<?= STREAM_URL ?>';
    } else {
      requestPin();
    }
  } catch(e) {
    requestPin();
  }
}

// ── PIN LIFECYCLE ─────────────────────────────────────────────────────────────
function showPhase(id) {
  ['phase-requesting', 'phase-waiting'].forEach(p => {
    document.getElementById(p)?.classList.toggle('active', p === id);
  });
}

async function requestPin() {
  showPhase('phase-requesting');
  document.getElementById('req-title').textContent = 'Requesting Access PIN';
  document.getElementById('req-sub').innerHTML =
    'Generating a one-time PIN…<br><span style="color:var(--muted2)">Check the server terminal window</span>';

  try {
    const r    = await fetch('auth.php?action=request_pin');
    const data = await r.json();
    if (data.ok) {
      pinExpiresAt = data.expires_at;
      showPhase('phase-waiting');
      document.getElementById('pin-input').value = '';
      document.getElementById('pin-input').focus();
      startCountdown();
    } else {
      setReqError('Server error — refresh the page.');
    }
  } catch(e) {
    setReqError('Cannot reach server. Check your network.');
  }
}

function setReqError(msg) {
  document.getElementById('req-title').textContent = 'Error';
  document.getElementById('req-sub').innerHTML = `<span style="color:var(--red)">${msg}</span>`;
}

function startCountdown() {
  clearInterval(pinTimer);
  updateCountdown();
  pinTimer = setInterval(() => {
    const rem = pinExpiresAt - Math.floor(Date.now() / 1000);
    if (rem <= 0) {
      clearInterval(pinTimer);
      showPhase('phase-requesting');
      document.getElementById('req-title').textContent = 'PIN Expired';
      document.getElementById('req-sub').innerHTML =
        'Requesting a fresh PIN…<br><span style="color:var(--muted2)">Check the server terminal again</span>';
      setTimeout(requestPin, 800);
    } else { updateCountdown(); }
  }, 1000);
}

function updateCountdown() {
  const rem = Math.max(0, pinExpiresAt - Math.floor(Date.now() / 1000));
  const m = Math.floor(rem / 60), s = rem % 60;
  const el = document.getElementById('pin-countdown');
  if (!el) return;
  el.textContent = m + ':' + String(s).padStart(2, '0');
  el.className = 'pin-countdown' + (rem <= 30 ? ' crit' : rem <= 60 ? ' warn' : '');
}

// ── PIN SUBMIT ────────────────────────────────────────────────────────────────
function toggleEye() {
  const f = document.getElementById('pin-input');
  const b = document.getElementById('eye-btn');
  f.type = f.type === 'password' ? 'text' : 'password';
  b.textContent = f.type === 'password' ? '👁' : '🙈';
  f.focus();
}

async function submitPin() {
  const field = document.getElementById('pin-input');
  const btn   = document.getElementById('connect-btn');
  const label = document.getElementById('btn-label');
  const errEl = document.getElementById('pin-error');
  const pin   = field.value.trim();

  if (!pin) { field.focus(); return; }

  btn.disabled    = true;
  label.innerHTML = '<span class="btn-spin"></span>VERIFYING…';
  errEl.textContent = '';
  field.classList.remove('error');

  try {
    const r    = await fetch('auth.php?action=auth', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin }),
    });
    const data = await r.json();

    if (data.ok) {
      label.textContent = '✓ AUTHORIZED';
      clearInterval(pinTimer);
      setTimeout(() => { window.location.href = data.redirect || '<?= STREAM_URL ?>'; }, 300);
    } else if (data.expired) {
      clearInterval(pinTimer);
      showPhase('phase-requesting');
      document.getElementById('req-title').textContent = 'PIN Expired';
      document.getElementById('req-sub').innerHTML =
        'Getting a fresh PIN…<br><span style="color:var(--muted2)">Check the terminal again</span>';
      setTimeout(requestPin, 600);
    } else {
      field.value       = '';
      field.classList.add('error');
      errEl.textContent = '⚠ ' + (data.error || 'Invalid PIN');
      const card = document.getElementById('auth-card');
      card.classList.remove('shaking');
      void card.offsetWidth;
      card.classList.add('shaking');
      btn.disabled      = false;
      label.textContent = 'CONNECT';
      field.focus();
    }
  } catch(e) {
    errEl.textContent = '⚠ Connection error — retry';
    btn.disabled      = false;
    label.textContent = 'CONNECT';
  }
}
</script>
</body>
</html>
<?php
}
