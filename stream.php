<?php
/**
 * LAN Stream v2 — Multi-Worker · Session Manager
 * ─────────────────────────────────────────────────────────────────────────────
 *  Auth        : Handled exclusively by auth.php — if session is absent or
 *                expired the browser is redirected there automatically.
 *  Concurrent  : PHP_CLI_SERVER_WORKERS + session_write_close() before I/O.
 *  Sessions    : Ctrl+Shift+K opens the session kick panel in the browser.
 */

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
define('CHUNK_SIZE',       1024 * 1024 * 8);   // 8 MB per flush
define('MAX_RATE',         0);            // 0 = unlimited
define('LOG_FILE',         __DIR__ . '/logs/stream.log');
define('SESSION_DIR',      __DIR__ . '/data/sess');
define('SESSION_REGISTRY', __DIR__ . '/data/sessions.json');
define('IS_WINDOWS',       PHP_OS_FAMILY === 'Windows');
define('SESSION_LIFETIME', 86400);        // 24 h session (must match auth.php)
define('AUTH_URL',         'auth.php');   // where to redirect unauthenticated requests
define('USE_X_SENDFILE',   isset($_SERVER['SERVER_SOFTWARE']) && strpos($_SERVER['SERVER_SOFTWARE'], 'Apache') !== false); // Auto-detect Apache for mod_xsendfile
define('ADMIN_PIN',        '2441');       // Hardcoded admin escalation PIN

// Streamable media extensions
define('ALLOWED_VIDEO',   ['mp4','mkv','webm','avi','mov','m4v','ts','flv','wmv','mpg','mpeg','3gp','ogv']);
define('ALLOWED_AUDIO',   ['mp3','wav','ogg','m4a','flac','aac','wma']);
define('ALLOWED_IMAGE',   ['jpg','jpeg','png','gif','webp','bmp','svg']);
define('ALLOWED_ARCHIVE', ['zip','rar','7z','tar','gz','bz2','xz']);
define('ALLOWED_EXT', array_merge(ALLOWED_VIDEO, ALLOWED_AUDIO, ALLOWED_IMAGE, ALLOWED_ARCHIVE));

// ─── MIME MAP ─────────────────────────────────────────────────────────────────
$mime_map = [
    // Video
    'mp4'  => 'video/mp4',        'mkv'  => 'video/x-matroska',
    'webm' => 'video/webm',       'avi'  => 'video/x-msvideo',
    'mov'  => 'video/quicktime',  'm4v'  => 'video/x-m4v',
    'ts'   => 'video/mp2t',       'flv'  => 'video/x-flv',
    'wmv'  => 'video/x-ms-wmv',   'mpg'  => 'video/mpeg',
    'mpeg' => 'video/mpeg',       '3gp'  => 'video/3gpp',
    'ogv'  => 'video/ogg',
    // Audio
    'mp3'  => 'audio/mpeg',       'wav'  => 'audio/wav',
    'ogg'  => 'audio/ogg',        'm4a'  => 'audio/mp4',
    'flac' => 'audio/flac',       'aac'  => 'audio/aac',
    'wma'  => 'audio/x-ms-wma',
    // Image
    'jpg'  => 'image/jpeg',       'jpeg' => 'image/jpeg',
    'png'  => 'image/png',        'gif'  => 'image/gif',
    'webp' => 'image/webp',       'bmp'  => 'image/bmp',
    'svg'  => 'image/svg+xml',
    // Archive
    'zip'  => 'application/zip',             'rar'  => 'application/vnd.rar',
    '7z'   => 'application/x-7z-compressed', 'tar'  => 'application/x-tar',
    'gz'   => 'application/gzip',            'bz2'  => 'application/x-bzip2',
    'xz'   => 'application/x-xz',
];

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
    header('Access-Control-Allow-Origin: *');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function json_error(int $code, string $msg): never {
    http_response_code($code);
    json_out(['error' => $msg]);
}

function format_bytes(int $bytes): string {
    if ($bytes <= 0) return '0 B';
    $units = ['B','KB','MB','GB','TB'];
    $i = min((int)floor(log($bytes, 1024)), 4);
    return round($bytes / (1024 ** $i), 2) . ' ' . $units[$i];
}

function get_media_type(string $name): ?string {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (in_array($ext, ALLOWED_VIDEO))   return 'video';
    if (in_array($ext, ALLOWED_AUDIO))   return 'audio';
    if (in_array($ext, ALLOWED_IMAGE))   return 'image';
    if (in_array($ext, ALLOWED_ARCHIVE)) return 'archive';
    return null;
}

function is_media_file(string $name): bool {
    return get_media_type($name) !== null;
}

/**
 * Resolve and validate a path from the request.
 * Prevents directory traversal. Normalises Windows drive letters.
 */
function safe_path(string $raw): string|false {
    $path = str_replace(['\\', "\0"], ['/', ''], rawurldecode($raw));
    if (strpos($path, '..') !== false) return false;
    if (IS_WINDOWS && preg_match('#^/([A-Za-z])(/.*)?$#', $path, $m)) {
        $path = strtoupper($m[1]) . ':' . ($m[2] ?? '/');
        $path = str_replace('/', '\\', $path);
    }
    return $path;
}

/** Convert User-Agent to a friendly device label. */
function parse_ua(string $ua): string {
    if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) return '📱 iOS';
    if (str_contains($ua, 'Android'))  return '📱 Android';
    if (str_contains($ua, 'Windows'))  return '🖥 Windows';
    if (str_contains($ua, 'Macintosh')) return '🍎 Mac';
    if (str_contains($ua, 'Linux'))    return '🐧 Linux';
    if (str_contains($ua, 'TV') || str_contains($ua, 'Smart')) return '📺 TV';
    return '🌐 Browser';
}

// ─── DRIVE / ROOT DISCOVERY ───────────────────────────────────────────────────
function get_roots(): array {
    $roots = [];
    if (IS_WINDOWS) {
        foreach (range('A', 'Z') as $letter) {
            $drive = $letter . ':\\';
            if (is_dir($drive)) {
                $roots[] = [
                    'label'    => $letter . ':',
                    'path'     => '/' . $letter,
                    'type'     => 'drive',
                    'readable' => is_readable($drive),
                ];
            }
        }
    } else {
        $skip  = ['/proc', '/sys', '/dev', '/run', '/boot', '/snap', '/lost+found'];
        $roots = [['label' => '/ (root)', 'path' => '/', 'type' => 'root', 'readable' => is_readable('/')]];
        $mfile = file_exists('/proc/mounts') ? '/proc/mounts' : '/etc/mtab';
        if (file_exists($mfile)) {
            foreach (file($mfile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $p  = preg_split('/\s+/', $line);
                $mp = $p[1] ?? '';
                if (!$mp || $mp === '/') continue;
                foreach ($skip as $s) { if (str_starts_with($mp, $s)) continue 2; }
                if (is_dir($mp) && is_readable($mp)) {
                    $roots[] = ['label' => basename($mp) ?: $mp, 'path' => $mp,
                                'type'  => 'mount', 'readable' => true, 'fs' => $p[2] ?? ''];
                }
            }
        }
        $seen  = [];
        $roots = array_values(array_filter($roots, function ($r) use (&$seen) {
            if (in_array($r['path'], $seen)) return false;
            $seen[] = $r['path'];
            return true;
        }));
    }
    return $roots;
}

// ─── DIRECTORY BROWSE ─────────────────────────────────────────────────────────
function browse_dir(string $dir, bool $admin = false): array {
    if (!is_dir($dir) || !is_readable($dir))
        return ['error' => 'Cannot read directory', 'dirs' => [], 'files' => []];

    $dirs = []; $files = [];
    $local_ignore = [];
    $ignore_file = $dir . DIRECTORY_SEPARATOR . '.lanignore';
    if (file_exists($ignore_file) && is_readable($ignore_file)) {
        $lines = file($ignore_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines !== false) {
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line !== '' && !str_starts_with($line, '#')) {
                    $local_ignore[] = strtolower($line);
                }
            }
        }
    }

    try {
        foreach (new DirectoryIterator($dir) as $item) {
            if ($item->isDot()) continue;
            $name = $item->getFilename();
            $lname = strtolower($name);
            
            // Always hide critical system folders and .lanignore-listed entries
            $ignore_list = ['$RECYCLE.BIN', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'Config.Msi'];
            if (in_array($name, $ignore_list) || in_array($lname, $local_ignore)) continue;
            
            // Hide dot-files from regular users; admins see everything
            if (!$admin && str_starts_with($name, '.')) continue;
            
            if ($item->isDir() && $item->isReadable()) {
                $dirs[] = [
                    'name'    => $name,
                    'path'    => rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . $name,
                    'hidden'  => str_starts_with($name, '.'),
                ];
            } elseif ($item->isFile()) {
                $mediaType = get_media_type($name);
                // Regular users: only media files. Admins: also dot-files (treat as text/raw)
                if (!$admin && $mediaType === null) continue;
                $sz = $item->getSize();
                $isDotFile = str_starts_with($name, '.');
                $files[] = [
                    'name'     => $name,
                    'path'     => $item->getRealPath() ?: ($dir . DIRECTORY_SEPARATOR . $name),
                    'size'     => $sz,
                    'size_fmt' => format_bytes($sz),
                    'ext'      => strtolower($item->getExtension()),
                    'mtime'    => $item->getMTime(),
                    'type'     => $mediaType ?? ($isDotFile ? 'dotfile' : 'other'),
                    'hidden'   => $isDotFile,
                ];
            }
        }
    } catch (Throwable) {
        return ['error' => 'Access denied', 'dirs' => [], 'files' => []];
    }
    usort($dirs,  fn($a, $b) => strcasecmp($a['name'], $b['name']));
    usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    return ['dirs' => $dirs, 'files' => $files, 'path' => $dir];
}

// ─── SESSION REGISTRY ─────────────────────────────────────────────────────────
// Thread-safe shared registry using exclusive file locks.
// Multiple PHP workers can safely read/write concurrently.

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
    // Open with 'c' — create if missing, don't truncate yet (avoid races)
    $fp = @fopen(SESSION_REGISTRY, 'c');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    rewind($fp);
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

function registry_update_activity(string $sid): void {
    // Throttled — write at most every 30 s to keep disk I/O low under load
    $s = registry_load();
    if (isset($s[$sid]) && time() - ($s[$sid]['last_activity'] ?? 0) > 30) {
        $s[$sid]['last_activity'] = time();
        registry_save($s);
    }
}

function registry_get_all(): array {
    $s = registry_load();
    $now = time();
    $clean = [];
    foreach ($s as $sid => $info) {
        if (($info['expires'] ?? 0) > $now) $clean[$sid] = $info;
    }
    if (count($clean) !== count($s)) registry_save($clean); // prune expired
    return array_values($clean);
}

/**
 * Destroy an arbitrary session by its ID.
 * Validates the format so callers cannot inject arbitrary paths.
 */
function destroy_session_by_id(string $sid): bool {
    // PHP session IDs are hex / alphanumeric
    if (!preg_match('/^[a-zA-Z0-9,\-]{10,128}$/', $sid)) return false;
    $file = SESSION_DIR . DIRECTORY_SEPARATOR . 'sess_' . $sid;
    if (file_exists($file)) @unlink($file);
    registry_remove($sid);
    return true;
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

function is_admin(): bool {
    return ($_SESSION['is_admin'] ?? false) === true;
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
session_set_cookie_params([
    'lifetime' => SESSION_LIFETIME,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_save_path(SESSION_DIR);
session_start();

// ─── AUTH GATE ────────────────────────────────────────────────────────────────
$action = $_GET['action'] ?? 'ui';

// ─── AUTH GATE ────────────────────────────────────────────────────────────────
if (!is_authorized()) {
    session_write_close();
    if ($action === 'ui') {
        header('Location: auth.php');
        exit;
    }
    http_response_code(401);
    json_out(['error' => 'Session expired', 'redirect' => 'auth.php']);
}

$current_sid = session_id();
session_write_close();
registry_update_activity($current_sid);

// ─── ROUTER ───────────────────────────────────────────────────────────────────
match ($action) {
    'roots'          => action_roots(),
    'browse'         => action_browse(),
    'stream'         => action_stream(),
    'hls_playlist'   => action_hls_playlist(),
    'info'           => action_info(),
    'logout'         => action_logout(),
    'list_sessions'  => action_list_sessions(),
    'kick_session'   => action_kick_session(),
    'verify_admin'   => action_verify_admin(),
    'revoke_admin'   => action_revoke_admin(),
    'ui'             => action_ui(),
    default          => json_error(404, 'Unknown action'),
};

// ─── ACTION: ROOTS ────────────────────────────────────────────────────────────
function action_roots(): void { json_out(get_roots()); }

// ─── ACTION: BROWSE ───────────────────────────────────────────────────────────
function action_browse(): void {
    $raw  = $_GET['path'] ?? '';
    if ($raw === '') json_out(['error' => 'No path specified', 'dirs' => [], 'files' => []]);
    $path = safe_path($raw);
    if ($path === false) json_error(403, 'Access denied');
    json_out(browse_dir($path, is_admin()));
}

// ─── ACTION: HLS PLAYLIST (ROUGH BYTE MAP FOR TS SEEKING) ─────────────────────
function action_hls_playlist(): void {
    $raw  = $_GET['path'] ?? '';
    $path = safe_path($raw);
    if (!$path || !file_exists($path) || !is_file($path)) json_error(404, 'File not found');
    
    $size = filesize($path);
    $duration = 0;
    
    // Get duration using ffprobe
    $cmd = 'ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 ' . escapeshellarg($path);
    $out = shell_exec($cmd);
    if (is_numeric(trim($out))) $duration = (float)trim($out);
    
    if ($duration <= 0) $duration = $size / (1024 * 1024); // Fallback: Assume 1MB/s
    
    header('Content-Type: application/vnd.apple.mpegurl');
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: no-store, no-cache');
    
    $segment_duration = 5.0; // 5 seconds per chunk roughly
    $total_segments = ceil($duration / $segment_duration);
    $bytes_per_segment = floor($size / $total_segments);
    
    echo "#EXTM3U\n";
    echo "#EXT-X-VERSION:4\n";
    echo "#EXT-X-TARGETDURATION:" . ceil($segment_duration) . "\n";
    echo "#EXT-X-MEDIA-SEQUENCE:0\n";
    echo "#EXT-X-PLAYLIST-TYPE:VOD\n";
    
    $current_offset = 0;
    $stream_url = '?action=stream&path=' . urlencode($path);
    
    for ($i = 0; $i < $total_segments; $i++) {
        $is_last = ($i == $total_segments - 1);
        $seg_bytes = $is_last ? ($size - $current_offset) : $bytes_per_segment;
        $seg_time = $is_last ? ($duration - ($i * $segment_duration)) : $segment_duration;
        
        echo "#EXTINF:" . number_format($seg_time, 4, '.', '') . ",\n";
        echo "#EXT-X-BYTERANGE:{$seg_bytes}@{$current_offset}\n";
        echo $stream_url . "\n";
        
        $current_offset += $seg_bytes;
    }
    
    echo "#EXT-X-ENDLIST\n";
    exit;
}

// ─── ACTION: INFO ─────────────────────────────────────────────────────────────
function action_info(): void {
    global $mime_map;
    $raw  = $_GET['path'] ?? '';
    $path = safe_path($raw);
    if (!$path || !file_exists($path) || !is_media_file(basename($path))) json_error(404, 'File not found');
    $size = filesize($path);
    $ext  = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    json_out([
        'name'     => basename($path),
        'path'     => $path,
        'size'     => $size,
        'size_fmt' => format_bytes($size),
        'mime'     => $mime_map[$ext] ?? 'video/mp4',
        'url'      => '?action=stream&path=' . urlencode($path),
    ]);
}

// ─── ACTION: STREAM ───────────────────────────────────────────────────────────
function action_stream(): void {
    global $mime_map;

    $raw  = $_GET['path'] ?? '';
    $path = safe_path($raw);
    if (!$path || !file_exists($path) || !is_file($path)) json_error(404, 'File not found');
    // Regular users: only whitelisted media types. Admins: any file including dot-files.
    if (!is_admin() && !is_media_file(basename($path)))
        json_error(403, 'Access denied — not a media file');
    if (!is_readable($path)) json_error(403, 'File not readable');

    $size = filesize($path);
    $ext  = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $mime = $mime_map[$ext] ?? 'video/mp4';

    log_event('STREAM ' . basename($path) . " | ua=" . ($_SERVER['HTTP_USER_AGENT'] ?? ''));

    $sendfile_path = IS_WINDOWS ? str_replace('/', '\\', $path) : $path;
    $disposition   = (get_media_type(basename($path)) === 'archive' || isset($_GET['dl'])) ? 'attachment' : 'inline';
    
    // ── mod_xsendfile fast path ───────────────────────────────────────────────
    // Apache handles Range negotiation, Content-Length, and byte serving itself.
    // PHP must NOT send Content-Range / Content-Length / 206 — those conflict
    // with mod_xsendfile and produce a silent 0-byte response.
    // On Windows the path in the header must use backslashes to match XSendFilePath.
    if (USE_X_SENDFILE) {
        header('Content-Type: ' . $mime);
        header('Content-Disposition: ' . $disposition . '; filename="' . addslashes(basename($path)) . '"');
        header('X-Sendfile: '   . $sendfile_path);
        exit;
    }

    // ── PHP streaming fallback ────────────────────────────────────────────────
    $start  = 0;
    $end    = $size - 1;
    $length = $size;

    if (isset($_SERVER['HTTP_RANGE'])) {
        if (!preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
            header('HTTP/1.1 416 Requested Range Not Satisfiable');
            header("Content-Range: bytes */$size");
            exit;
        }
        $rs = $m[1] !== '' ? (int)$m[1] : 0;
        $re = $m[2] !== '' ? (int)$m[2] : $size - 1;
        if ($rs > $re || $rs >= $size || $re >= $size) {
            header('HTTP/1.1 416 Requested Range Not Satisfiable');
            header("Content-Range: bytes */$size");
            exit;
        }
        $start = $rs; $end = $re; $length = $end - $start + 1;
        header('HTTP/1.1 206 Partial Content');
        header("Content-Range: bytes $start-$end/$size");
    } else {
        header('HTTP/1.1 200 OK');
    }

    header('Content-Type: '    . $mime);
    header('Content-Disposition: ' . $disposition . '; filename="' . addslashes(basename($path)) . '"');
    header('Content-Length: '  . $length);
    header('Accept-Ranges: bytes');
    header('Connection: keep-alive');
    header('Cache-Control: no-store, no-cache');
    header('X-Content-Type-Options: nosniff');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: Range');

    $etag = md5($path . $size . filemtime($path));
    header("ETag: \"$etag\"");
    if (isset($_SERVER['HTTP_IF_RANGE']) && trim($_SERVER['HTTP_IF_RANGE'], '"') !== $etag) {
        $start = 0; $end = $size - 1; $length = $size;
    }

    if (ob_get_level()) ob_end_clean();
    ini_set('output_buffering', '0');
    ini_set('zlib.output_compression', '0');

    $fp = fopen($path, 'rb');
    if (!$fp) json_error(500, 'Cannot open file');

    fseek($fp, $start);
    set_time_limit(0);
    ignore_user_abort(false);

    $rem = $length;
    while (!feof($fp) && $rem > 0 && !connection_aborted()) {
        $chunk = fread($fp, min(CHUNK_SIZE, $rem));
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
        flush();
        $rem -= strlen($chunk);
        if (MAX_RATE > 0) usleep((int)((strlen($chunk) / MAX_RATE) * 1_000_000));
    }
    fclose($fp);
    log_event('DONE ' . basename($path) . ' | sent=' . format_bytes($length - $rem));
    exit;
}





// ─── ACTION: LOGOUT ───────────────────────────────────────────────────────────
function action_logout(): void {
    session_start();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '?';
    session_deauthorize();
    log_event("LOGOUT | ip=$ip");
    print_system_status("LOGOUT", "Device logged out manually.", "Session cleared.");
    // If called from the browser (not fetch), do a hard redirect
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    if (str_contains($accept, 'text/html') && !isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
        header('Location: auth.php');
        exit;
    }
    json_out(['ok' => true, 'redirect' => 'auth.php']);
}



// ─── ACTION: LIST SESSIONS ────────────────────────────────────────────────────
function action_list_sessions(): void {
    $sessions    = registry_get_all();
    $current_sid = $_COOKIE[session_name()] ?? '';
    $out = [];
    foreach ($sessions as $s) {
        $out[] = [
            'sid'           => $s['sid'],
            'ip'            => $s['ip']  ?? '?',
            'device'        => parse_ua($s['ua'] ?? ''),
            'login_time'    => $s['login_time']    ?? 0,
            'last_activity' => $s['last_activity'] ?? 0,
            'expires'       => $s['expires']       ?? 0,
            'is_current'    => ($s['sid'] === $current_sid),
        ];
    }
    json_out($out);
}

// ─── ACTION: KICK SESSION ─────────────────────────────────────────────────────
function action_kick_session(): void {
    $target  = trim($_GET['sid'] ?? '');
    $current = $_COOKIE[session_name()] ?? '';
    if ($target === '')        json_error(400, 'No session ID provided');
    if ($target === $current)  json_error(400, 'Cannot kick your own session');
    if (destroy_session_by_id($target)) {
        log_event("KICK sid=$target by " . ($_SERVER['REMOTE_ADDR'] ?? '?'));
        print_system_status("KICKED", "Session kicked by admin.", "Session invalidated.");
        json_out(['ok' => true]);
    } else {
        json_error(400, 'Invalid session ID');
    }
}

// ─── ACTION: VERIFY ADMIN ────────────────────────────────────────────────────
function action_verify_admin(): void {
    $pin = trim($_POST['pin'] ?? $_GET['pin'] ?? '');
    if ($pin === ADMIN_PIN) {
        // Re-open session just long enough to set the flag
        session_start();
        $_SESSION['is_admin'] = true;
        session_write_close();
        log_event('ADMIN_ESCALATE | ip=' . ($_SERVER['REMOTE_ADDR'] ?? '?'));
        json_out(['ok' => true]);
    } else {
        log_event('ADMIN_FAIL | ip=' . ($_SERVER['REMOTE_ADDR'] ?? '?'));
        json_error(403, 'Invalid PIN');
    }
}

// ─── ACTION: REVOKE ADMIN ─────────────────────────────────────────────────────
function action_revoke_admin(): void {
    session_start();
    $_SESSION['is_admin'] = false;
    session_write_close();
    log_event('ADMIN_REVOKE | ip=' . ($_SERVER['REMOTE_ADDR'] ?? '?'));
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
<title>⚡ LAN Stream</title>
<meta name="description" content="LAN zero-latency video streamer with PIN authorization and session management.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap">
<script src="https://cdn.jsdelivr.net/npm/hls.js@1"></script>
<style>
/* ── RESET & ROOT ─────────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:       #080810;
  --surface:  #0f0f18;
  --surface2: #13131e;
  --border:   #1c1c2a;
  --border2:  #252535;
  --accent:   #00e5ff;
  --accent2:  #7b2fff;
  --accent3:  #ff6b35;
  --text:     #e2e2f0;
  --muted:    #50506a;
  --muted2:   #3a3a52;
  --green:    #00ffaa;
  --yellow:   #ffd700;
  --red:      #ff4466;
  --r:        5px;
  --trans:    .15s cubic-bezier(.4,0,.2,1);
  --header-h:   48px;
  --info-h:     40px;
  --stats-h:    52px;
  --controls-h: 52px;
}

html, body { height: 100%; height: 100dvh; overflow: hidden; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  display: flex;
  flex-direction: column;
}

/* ── SCANLINES ─────────────────────────────────────────────────────────────── */
body::before {
  content: '';
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,.07) 2px, rgba(0,0,0,.07) 4px),
    linear-gradient(rgba(0,229,255,.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,.015) 1px, transparent 1px);
  background-size: auto, 44px 44px, 44px 44px;
}



/* ═══════════════════════════════════════════════════════════════════════════
   SESSION MANAGER PANEL
   ═══════════════════════════════════════════════════════════════════════════ */
#panel-backdrop {
  position: fixed; inset: 0; z-index: 799;
  background: rgba(0,0,0,.45);
  display: none;
  animation: bdIn .25s;
}
#panel-backdrop.open { display: block; }
@keyframes bdIn { from { opacity: 0; } to { opacity: 1; } }

#session-panel {
  position: fixed;
  top: 0; right: 0; bottom: 0;
  width: 304px;
  background: var(--surface);
  border-left: 1px solid var(--border2);
  z-index: 800;
  transform: translateX(100%);
  transition: transform .28s cubic-bezier(.4,0,.2,1);
  display: flex; flex-direction: column;
  box-shadow: -20px 0 60px rgba(0,0,0,.6);
}
#session-panel.open { transform: translateX(0); }

.sp-header {
  padding: 0 14px;
  height: 48px;
  display: flex; align-items: center; gap: 8px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  position: relative;
}
.sp-header::after {
  content: '';
  position: absolute; bottom: -1px; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, var(--accent2), transparent);
  opacity: .4;
}

.sp-title {
  font-size: 9px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; color: var(--accent2); flex: 1;
}
.sp-shortcut {
  font-size: 8px; color: var(--muted2);
  border: 1px solid var(--border2); padding: 2px 5px; border-radius: 2px;
}
.sp-icon-btn {
  background: none; border: none; color: var(--muted);
  cursor: pointer; font-size: 15px; padding: 5px;
  transition: color var(--trans); line-height: 1; border-radius: 3px;
  display: grid; place-items: center;
}
.sp-icon-btn:hover { color: var(--text); background: rgba(255,255,255,.04); }

.session-list {
  flex: 1; overflow-y: auto; min-height: 0;
  scrollbar-width: thin; scrollbar-color: var(--border2) transparent;
}

.sess-card {
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  transition: background var(--trans);
  position: relative;
}
.sess-card:hover { background: rgba(255,255,255,.02); }
.sess-card.current {
  background: rgba(0,229,255,.03);
  border-left: 2px solid var(--accent);
  padding-left: 12px;
}

.sess-top {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 8px;
}
.sess-badge {
  font-size: 7px; font-weight: 700; letter-spacing: 1px;
  padding: 2px 6px; border-radius: 2px; text-transform: uppercase;
  flex-shrink: 0;
}
.sess-badge.cur { background: rgba(0,229,255,.15); color: var(--accent); }
.sess-badge.act { background: rgba(0,255,170,.1);  color: var(--green); }

.sess-device { font-size: 12px; color: var(--text); flex: 1;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.sess-meta {
  display: flex; flex-direction: column; gap: 3px;
  margin-bottom: 10px;
}
.sess-meta-row {
  display: flex; align-items: center;
  font-size: 9px; color: var(--muted2);
}
.sess-meta-key { width: 56px; color: var(--muted); flex-shrink: 0; }
.sess-meta-val { color: var(--muted2); font-family: 'JetBrains Mono', monospace; }

.sess-meta-val.ip { color: var(--text); }

.sess-bar {
  height: 2px; background: var(--border);
  border-radius: 1px; margin-bottom: 10px; overflow: hidden;
}
.sess-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--green), var(--accent));
  border-radius: 1px;
  transition: width .3s;
}

.kick-btn {
  padding: 5px 11px;
  background: rgba(255,68,102,.07);
  border: 1px solid rgba(255,68,102,.22);
  border-radius: 3px;
  color: var(--red); font-family: inherit;
  font-size: 9px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
  cursor: pointer; transition: all var(--trans);
}
.kick-btn:hover {
  background: rgba(255,68,102,.16);
  border-color: rgba(255,68,102,.5);
  box-shadow: 0 0 10px rgba(255,68,102,.2);
}

.sess-card.kicked { opacity: 0; transform: translateX(30px); transition: all .35s ease; }

.sess-empty {
  padding: 32px 16px; text-align: center;
  font-size: 11px; color: var(--muted); line-height: 2;
}

.sp-footer {
  padding: 12px 14px;
  border-top: 1px solid var(--border); flex-shrink: 0;
  display: flex; flex-direction: column; gap: 8px;
}
.sp-count { font-size: 9px; color: var(--muted2); text-align: center; letter-spacing: .5px; }

.kick-all-btn {
  width: 100%; padding: 9px;
  background: rgba(255,68,102,.08);
  border: 1px solid rgba(255,68,102,.28);
  border-radius: 4px;
  color: var(--red); font-family: inherit;
  font-size: 10px; font-weight: 700; letter-spacing: 1px;
  cursor: pointer; transition: all var(--trans);
}
.kick-all-btn:hover { background: rgba(255,68,102,.18); box-shadow: 0 0 16px rgba(255,68,102,.2); }
.kick-all-btn:disabled { opacity: .35; cursor: not-allowed; }

.sp-loading {
  padding: 28px 16px; text-align: center;
  font-size: 11px; color: var(--muted);
}
.sp-loading::after {
  content: '';
  display: inline-block; width: 11px; height: 11px;
  border: 1.5px solid var(--border2); border-top-color: var(--accent2);
  border-radius: 50%; animation: spin .7s linear infinite;
  vertical-align: middle; margin-left: 8px;
}

/* ── HEADER ────────────────────────────────────────────────────────────────── */
header {
  position: relative; z-index: 10;
  display: flex; align-items: center; gap: 12px;
  padding: 0 16px;
  height: var(--header-h);
  border-bottom: 1px solid var(--border);
  background: rgba(8,8,16,.97);
  backdrop-filter: blur(12px);
  flex-shrink: 0;
}
.logo {
  width: 30px; height: 30px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: var(--r);
  display: grid; place-items: center;
  font-size: 14px;
  box-shadow: 0 0 20px rgba(0,229,255,.25);
  flex-shrink: 0;
}
header h1 { font-family: 'Syne', sans-serif; font-size: 18px; font-weight: 800; letter-spacing: -.5px; }
header h1 em { color: var(--accent); font-style: normal; }

.h-meta {
  margin-left: auto; display: flex; gap: 8px; align-items: center;
  font-size: 10px; color: var(--muted);
}
.dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--green); box-shadow: 0 0 8px var(--green);
  animation: blink 2s infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }

.h-badge {
  font-size: 9px; font-weight: 700; letter-spacing: 1px;
  padding: 2px 8px; border-radius: 3px;
  border: 1px solid var(--green); color: var(--green);
  box-shadow: 0 0 10px rgba(0,255,170,.1);
  display: inline-block;
}
.h-btn {
  padding: 3px 9px; border-radius: 3px;
  font-family: inherit; font-size: 9px; font-weight: 700;
  letter-spacing: 1px; cursor: pointer;
  transition: all var(--trans);
  display: inline-flex;
  align-items: center;
}
#btn-sessions {
  border: 1px solid var(--border2); background: transparent; color: var(--muted);
}
#btn-sessions:hover { border-color: var(--accent2); color: var(--accent2); box-shadow: 0 0 10px rgba(123,47,255,.2); }
#btn-logout {
  border: 1px solid rgba(255,68,102,.35); background: transparent; color: var(--red);
}
#btn-logout:hover { border-color: var(--red); box-shadow: 0 0 10px rgba(255,68,102,.15); }

/* ── ADMIN BUTTON ─────────────────────────────────────────────────────────── */
#btn-admin {
  border: 1px solid rgba(255,215,0,.3); background: transparent; color: var(--yellow);
  position: relative;
}
#btn-admin:hover { border-color: var(--yellow); box-shadow: 0 0 12px rgba(255,215,0,.22); }
#btn-admin.active {
  background: rgba(255,215,0,.12);
  border-color: var(--yellow);
  color: var(--yellow);
  box-shadow: 0 0 14px rgba(255,215,0,.28);
}
#btn-admin .admin-pip {
  position: absolute; top: -3px; right: -3px;
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--yellow); box-shadow: 0 0 6px var(--yellow);
  display: none;
}
#btn-admin.active .admin-pip { display: block; }

/* ── ADMIN PIN MODAL ─────────────────────────────────────────────────────── */
#admin-modal-backdrop {
  position: fixed; inset: 0; z-index: 1100;
  background: rgba(0,0,0,.65); backdrop-filter: blur(6px);
  display: none; align-items: center; justify-content: center;
}
#admin-modal-backdrop.open { display: flex; animation: bdIn .2s; }

.admin-modal {
  background: var(--surface);
  border: 1px solid rgba(255,215,0,.25);
  border-radius: 8px;
  padding: 28px 28px 22px;
  width: 320px;
  box-shadow: 0 0 60px rgba(255,215,0,.1), 0 20px 60px rgba(0,0,0,.8);
  display: flex; flex-direction: column; gap: 16px;
  position: relative;
}
.admin-modal::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--yellow), var(--accent2));
  border-radius: 8px 8px 0 0;
}
.admin-modal-title {
  display: flex; align-items: center; gap: 10px;
  font-family: 'Syne', sans-serif; font-size: 16px; font-weight: 800;
  color: var(--yellow); letter-spacing: -.3px;
}
.admin-modal-title span { font-size: 20px; }
.admin-modal-sub {
  font-size: 10px; color: var(--muted); line-height: 1.7;
  letter-spacing: .3px;
}
.admin-pin-field {
  display: flex; flex-direction: column; gap: 6px;
}
.admin-pin-label {
  font-size: 9px; font-weight: 700; letter-spacing: 1.5px;
  text-transform: uppercase; color: var(--muted);
}
.admin-pin-input {
  width: 100%; padding: 10px 14px;
  background: var(--bg);
  border: 1px solid rgba(255,215,0,.25);
  border-radius: 5px;
  color: var(--yellow); font-family: 'JetBrains Mono', monospace;
  font-size: 18px; font-weight: 700; letter-spacing: 6px;
  outline: none; text-align: center;
  transition: border-color .15s, box-shadow .15s;
}
.admin-pin-input::placeholder { letter-spacing: 2px; font-size: 13px; color: var(--muted2); }
.admin-pin-input:focus {
  border-color: rgba(255,215,0,.55);
  box-shadow: 0 0 16px rgba(255,215,0,.12);
}
.admin-pin-input.error {
  border-color: var(--red);
  animation: shake .3s ease;
}
.admin-pin-error {
  font-size: 10px; color: var(--red);
  text-align: center; min-height: 14px;
  letter-spacing: .3px;
}
@keyframes shake {
  0%,100% { transform: translateX(0); }
  25%      { transform: translateX(-6px); }
  75%      { transform: translateX(6px); }
}
.admin-modal-actions {
  display: flex; gap: 8px;
}
.admin-cancel-btn {
  flex: 1; padding: 9px;
  background: transparent; border: 1px solid var(--border2);
  border-radius: 4px; color: var(--muted);
  font-family: inherit; font-size: 10px; font-weight: 700; letter-spacing: 1px;
  cursor: pointer; transition: all .15s;
}
.admin-cancel-btn:hover { border-color: var(--muted); color: var(--text); }
.admin-confirm-btn {
  flex: 2; padding: 9px;
  background: rgba(255,215,0,.12); border: 1px solid rgba(255,215,0,.4);
  border-radius: 4px; color: var(--yellow);
  font-family: inherit; font-size: 10px; font-weight: 700; letter-spacing: 1px;
  cursor: pointer; transition: all .15s;
}
.admin-confirm-btn:hover {
  background: rgba(255,215,0,.22);
  box-shadow: 0 0 14px rgba(255,215,0,.2);
}

/* Admin revoke band shown in header when active */
.admin-active-band {
  display: none;
  font-size: 8px; font-weight: 700; letter-spacing: 1.5px;
  padding: 2px 7px; border-radius: 2px;
  background: rgba(255,215,0,.15); color: var(--yellow);
  border: 1px solid rgba(255,215,0,.3);
  text-transform: uppercase;
  cursor: pointer;
  transition: all .15s;
}
.admin-active-band:hover { background: rgba(255,215,0,.28); }
.admin-active-band.show { display: inline-block; }

/* Hidden-file badge for admin view */
.item-hidden-badge {
  font-size: 7px; font-weight: 700; letter-spacing: .5px;
  padding: 1px 4px; border-radius: 2px;
  background: rgba(255,215,0,.15); color: var(--yellow);
  border: 1px solid rgba(255,215,0,.25); flex-shrink: 0;
}

/* ── MAIN LAYOUT ───────────────────────────────────────────────────────────── */
.main {
  position: relative; z-index: 1;
  display: grid; grid-template-columns: 260px 1fr;
  flex: 1 1 0; min-height: 0; overflow: hidden;
}

/* ── LEFT PANEL ────────────────────────────────────────────────────────────── */
.browser-pane {
  display: flex; flex-direction: column;
  border-right: 1px solid var(--border);
  overflow: hidden; background: var(--surface); min-height: 0;
}
.pane-header {
  padding: 0 12px; height: 36px;
  font-size: 9px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; color: var(--muted);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px; flex-shrink: 0;
}
.breadcrumb {
  padding: 0 10px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 4px; flex-wrap: wrap;
  flex-shrink: 0; background: var(--surface2);
  min-height: 34px; max-height: 60px; overflow: hidden;
}
.crumb {
  font-size: 10px; color: var(--muted); cursor: pointer;
  padding: 2px 5px; border-radius: 3px;
  transition: color var(--trans), background var(--trans);
  white-space: nowrap; max-width: 110px;
  overflow: hidden; text-overflow: ellipsis;
}
.crumb:hover { color: var(--accent); background: rgba(0,229,255,.07); }
.crumb-sep { font-size: 9px; color: var(--muted2); }
.crumb:last-child { color: var(--text); cursor: default; }
.crumb:last-child:hover { background: transparent; color: var(--text); }

.drives-row {
  padding: 7px 10px;
  display: flex; gap: 5px; flex-wrap: wrap;
  flex-shrink: 0; border-bottom: 1px solid var(--border);
  background: var(--surface2); max-height: 72px; overflow: hidden;
}
.drive-btn {
  padding: 3px 9px; border-radius: 3px;
  border: 1px solid var(--border2); background: var(--surface);
  color: var(--muted); font-family: inherit; font-size: 10px; font-weight: 700;
  cursor: pointer; transition: all var(--trans); letter-spacing: 1px;
}
.drive-btn:hover { border-color: var(--accent2); color: var(--accent2); box-shadow: 0 0 10px rgba(123,47,255,.2); }
.drive-btn.active { background: rgba(123,47,255,.15); border-color: var(--accent2); color: var(--accent2); }

.file-tree { flex: 1 1 0; overflow-y: auto; min-height: 0; scrollbar-width: thin; scrollbar-color: var(--border2) transparent; }

.tree-item {
  display: flex; align-items: center; gap: 8px;
  padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,.025);
  cursor: pointer; font-size: 11px;
  transition: background var(--trans); user-select: none;
}
.tree-item:hover { background: rgba(255,255,255,.03); }
.tree-item.is-dir .item-name { color: var(--text); }
.tree-item.is-dir:hover .item-name { color: var(--yellow); }
.tree-item.is-file .item-name { color: var(--muted); }
.tree-item.is-file:hover .item-name { color: var(--accent); }
.tree-item.active-file { background: rgba(0,229,255,.07); }
.tree-item.active-file .item-name { color: var(--accent); }
.item-icon { font-size: 12px; flex-shrink: 0; width: 16px; text-align: center; }
.item-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.item-size { font-size: 9px; color: var(--muted2); flex-shrink: 0; }
.item-ext {
  font-size: 8px; font-weight: 700; letter-spacing: 1px;
  padding: 1px 4px; border-radius: 2px;
  background: rgba(123,47,255,.2); color: var(--accent2); flex-shrink: 0;
}
.tree-empty { padding: 28px 16px; text-align: center; font-size: 11px; color: var(--muted); line-height: 1.8; }
.tree-loading { padding: 18px 16px; text-align: center; font-size: 11px; color: var(--muted); }
.tree-loading::after {
  content: ''; display: inline-block; width: 11px; height: 11px;
  border: 1.5px solid var(--border2); border-top-color: var(--accent);
  border-radius: 50%; animation: spin .7s linear infinite;
  vertical-align: middle; margin-left: 8px;
}
.tree-error {
  padding: 10px 12px; margin: 8px;
  background: rgba(255,68,102,.08); border: 1px solid rgba(255,68,102,.2);
  border-radius: var(--r); font-size: 10px; color: #ff7090;
}

/* ── RIGHT PANEL ───────────────────────────────────────────────────────────── */
.player-pane {
  display: flex; flex-direction: column;
  overflow-y: auto; overflow-x: hidden; min-height: 0;
  scrollbar-width: thin; scrollbar-color: var(--border2) transparent;
}
.video-wrap {
  position: relative; background: #000;
  width: 100%; aspect-ratio: 16 / 9;
  flex-shrink: 0; overflow: hidden;
}
video { width: 100%; height: 100%; display: block; outline: none; object-fit: contain; background: #000; }
.placeholder {
  position: absolute; inset: 0;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 10px;
  color: var(--muted); font-size: 12px;
}
.ph-icon {
  width: 56px; height: 56px; border: 1.5px solid var(--border2);
  border-radius: 50%; display: grid; place-items: center;
  font-size: 22px; color: var(--muted2);
}

/* ── INFO ROW ──────────────────────────────────────────────────────────────── */
.info-row {
  padding: 0 14px; height: var(--info-h);
  border-top: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
  background: rgba(0,0,0,.4); flex-shrink: 0; overflow: hidden;
}
.now-playing { font-size: 12px; font-weight: 600; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tag {
  padding: 2px 7px; border-radius: 3px;
  font-size: 9px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
  border: 1px solid var(--border2); color: var(--muted); flex-shrink: 0;
}
.tag.live { border-color: var(--green); color: var(--green); box-shadow: 0 0 8px rgba(0,255,170,.15); }

/* ── STATS STRIP ───────────────────────────────────────────────────────────── */
.stats-strip {
  display: grid; grid-template-columns: repeat(4, 1fr);
  border-top: 1px solid var(--border); background: var(--surface2);
  height: var(--stats-h); flex-shrink: 0;
}
.stat-cell {
  padding: 6px 10px; border-right: 1px solid var(--border);
  display: flex; flex-direction: column; justify-content: center; gap: 2px;
}
.stat-cell:last-child { border-right: none; }
.stat-label { font-size: 8px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); }
.stat-value { font-size: 12px; font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; }

/* ── CONTROLS ──────────────────────────────────────────────────────────────── */
.controls {
  padding: 0 12px; height: var(--controls-h);
  display: flex; align-items: center; gap: 7px; flex-wrap: nowrap;
  border-top: 1px solid var(--border); background: var(--surface);
  flex-shrink: 0; overflow: hidden;
}
.btn {
  padding: 5px 11px; border-radius: var(--r);
  border: 1px solid var(--border2); background: transparent; color: var(--text);
  font-family: inherit; font-size: 11px;
  cursor: pointer; transition: all var(--trans);
  display: flex; align-items: center; gap: 4px;
  white-space: nowrap; flex-shrink: 0;
}
.btn:hover { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 12px rgba(0,229,255,.12); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: #000; font-weight: 700; }
.btn.primary:hover { background: #00cfec; box-shadow: 0 0 18px rgba(0,229,255,.35); color: #000; }
.btn:disabled { opacity: .35; cursor: not-allowed; }

.url-group {
  margin-left: auto; display: flex; gap: 6px; align-items: center;
  overflow: hidden; flex-shrink: 1; min-width: 0;
}
.url-input {
  width: clamp(100px, 14vw, 220px);
  padding: 4px 8px; background: var(--bg);
  border: 1px solid var(--border2); border-radius: var(--r);
  color: var(--accent); font-family: inherit; font-size: 10px; outline: none; min-width: 0;
}
.url-input:focus { border-color: var(--accent); }

/* ── TOAST ─────────────────────────────────────────────────────────────────── */
#toast {
  position: fixed; bottom: 18px; right: 18px;
  background: var(--surface); border: 1px solid var(--accent);
  color: var(--accent); padding: 8px 14px;
  border-radius: var(--r); font-size: 11px; z-index: 900;
  transform: translateY(40px); opacity: 0;
  transition: all .2s; pointer-events: none;
  box-shadow: 0 0 20px rgba(0,229,255,.2);
}
#toast.on { transform: translateY(0); opacity: 1; }
#toast.err { border-color: var(--red); color: var(--red); box-shadow: 0 0 20px rgba(255,68,102,.2); }

/* ── MEDIA MODAL ───────────────────────────────────────────────────────────── */
#media-modal {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,.6); backdrop-filter: blur(8px);
  display: none; align-items: center; justify-content: center;
  flex-direction: column; animation: bdIn .25s; padding: 20px;
}
#media-modal.open { display: flex; }
.modal-content {
  position: relative; max-width: 90%; max-height: 80%;
  display: flex; flex-direction: column; align-items: center; gap: 15px;
}
.modal-content img { max-width: 100%; max-height: 70vh; object-fit: contain; border-radius: var(--r); box-shadow: 0 10px 40px rgba(0,0,0,.8); }
.modal-content audio { width: 300px; max-width: 100%; outline: none; }
.modal-close {
  position: absolute; top: 20px; right: 20px;
  background: rgba(255,255,255,.1); border: none; color: #fff;
  width: 40px; height: 40px; border-radius: 50%; font-size: 18px;
  cursor: pointer; transition: background .2s; z-index: 1001;
}
.modal-close:hover { background: rgba(255,255,255,.2); }
.modal-dl-btn {
  padding: 8px 16px; border-radius: var(--r);
  background: var(--accent); color: #000; font-weight: 700; font-size: 12px;
  text-decoration: none; cursor: pointer; transition: all .2s;
}
.modal-dl-btn:hover { background: #00cfec; box-shadow: 0 0 15px rgba(0,229,255,.3); }

/* ── SCROLLBAR ─────────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 3px; height: 3px; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

/* ── RESPONSIVE ────────────────────────────────────────────────────────────── */
@media (max-width: 680px) {
  :root { --header-h:44px; --info-h:36px; --stats-h:44px; --controls-h:48px; }
  .main { grid-template-columns: 1fr; grid-template-rows: calc((100dvh - var(--header-h)) * .5) calc((100dvh - var(--header-h)) * .5); }
  .browser-pane { border-right: none; border-bottom: 1px solid var(--border); overflow: hidden; }
  .player-pane { overflow-y: auto; }
  .stats-strip { grid-template-columns: repeat(2, 1fr); }
  .url-group { display: none; }
  
  /* Compact header on mobile screens to prevent overflow */
  header {
    gap: 6px;
    padding: 0 8px;
  }
  .logo {
    width: 24px; height: 24px;
    font-size: 11px;
  }
  header h1 {
    font-size: 14px;
  }
  .h-meta {
    gap: 4px;
  }
  .dot { display: none; }
  #srv-addr { display: none; }
  #os-tag { display: none; }
  
  /* Convert authorized badge to padlock icon only */
  .h-badge {
    padding: 2px 4px;
    font-size: 0;
  }
  .h-badge::before {
    content: '🔒';
    font-size: 10px;
  }
  
  /* Convert SESSIONS button to icon only */
  #btn-sessions {
    font-size: 0;
    padding: 3px 6px;
  }
  #btn-sessions::before {
    content: '👥';
    font-size: 11px;
  }
  
  /* Convert DISCONNECT button to icon only */
  #btn-logout {
    font-size: 0;
    padding: 3px 6px;
  }
  #btn-logout::before {
    content: '📤';
    font-size: 11px;
  }
  
  /* Convert ADMIN button to icon only */
  #btn-admin {
    font-size: 0;
    padding: 3px 6px;
  }
  #btn-admin::before {
    content: '🛡️';
    font-size: 11px;
  }
  .admin-active-band { display: none !important; }
  
  #session-panel { width: 100%; border-left: none; border-top: 1px solid var(--border2); }
  .auth-card { width: calc(100% - 32px); max-width: 360px; }
}
@media (max-height: 480px) {
  :root { --stats-h: 0px; }
  .stats-strip { display: none; }
}
</style>
</head>
<body>



<!-- ═══════════════════════════════ SESSION PANEL ════════════════════════════ -->
<div id="panel-backdrop" onclick="closeSessionPanel()"></div>
<div id="session-panel" role="dialog" aria-label="Session Manager">
  <div class="sp-header">
    <span class="sp-title">⊞ Session Manager</span>
    <span class="sp-shortcut">Ctrl+Shift+K</span>
    <button class="sp-icon-btn" id="sp-refresh-btn" onclick="loadSessions()" title="Refresh">↺</button>
    <button class="sp-icon-btn" onclick="closeSessionPanel()" title="Close">✕</button>
  </div>
  <div class="session-list" id="session-list">
    <div class="sp-loading">Loading sessions</div>
  </div>
  <div class="sp-footer">
    <div class="sp-count" id="sp-count"></div>
    <button class="kick-all-btn" id="kick-all-btn" onclick="kickAllOthers()" disabled>
      ⚡ KICK ALL OTHERS
    </button>
  </div>
</div>

<!-- ═══════════════════════════════ MEDIA MODAL ══════════════════════════════ -->
<div id="media-modal" onclick="if(event.target===this) closeMediaModal()">
  <button class="modal-close" onclick="closeMediaModal()">✕</button>
  <div class="modal-content">
    <img id="modal-img" style="display:none">
    <audio id="modal-audio" controls style="display:none"></audio>
    <div id="modal-archive" style="display:none; text-align:center; padding: 40px; background:var(--surface); border-radius:var(--r); border:1px solid var(--border)">
      <div style="font-size:60px; margin-bottom:10px">📦</div>
      <div id="modal-archive-name" style="font-weight:700; font-size:14px; color:var(--text); margin-bottom:5px"></div>
      <div id="modal-archive-size" style="font-size:11px; color:var(--muted); margin-bottom:20px"></div>
    </div>
    <a id="modal-dl" class="modal-dl-btn" href="#" download>Download File</a>
  </div>
</div>

<!-- ══════════════════════════════ ADMIN PIN MODAL ═══════════════════════════════ -->
<div id="admin-modal-backdrop" onclick="if(event.target===this)closeAdminModal()">
  <div class="admin-modal" role="dialog" aria-label="Admin PIN">
    <div class="admin-modal-title"><span>🛡️</span> Admin Mode</div>
    <div class="admin-modal-sub">Enter the administrator PIN to elevate your session.<br>Admin access unlocks hidden files and session management.</div>
    <div class="admin-pin-field">
      <div class="admin-pin-label">PIN</div>
      <input id="admin-pin-input" class="admin-pin-input" type="password"
             maxlength="8" placeholder="••••"
             autocomplete="off"
             oninput="clearPinError()"
             onkeydown="if(event.key==='Enter')confirmAdminPin()">
      <div class="admin-pin-error" id="admin-pin-error"></div>
    </div>
    <div class="admin-modal-actions">
      <button class="admin-cancel-btn" onclick="closeAdminModal()">Cancel</button>
      <button class="admin-confirm-btn" id="admin-confirm-btn" onclick="confirmAdminPin()">🛡️ VERIFY PIN</button>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════ MAIN CHROME ══════════════════════════════════ -->
<header>
  <div class="logo">⚡</div>
  <h1>LAN<em>Stream</em></h1>
  <div class="h-meta">
    <div class="dot"></div>
    <span id="srv-addr">—</span>
    <span id="os-tag" style="color:var(--accent2)"></span>
    <span class="h-badge" id="h-badge">🔒 AUTHORIZED</span>
    <span class="admin-active-band" id="admin-active-band" onclick="revokeAdmin()" title="Click to exit Admin Mode">⚡ ADMIN • click to exit</span>
    <button class="h-btn" id="btn-admin" onclick="onAdminBtnClick()" title="Toggle Admin Mode">🛡️ ADMIN<span class="admin-pip"></span></button>
    <button class="h-btn" id="btn-sessions" onclick="openSessionPanel()" title="Ctrl+Shift+K" style="display:none">⊞ SESSIONS</button>
    <button class="h-btn" id="btn-logout" onclick="doLogout()">⏻ DISCONNECT</button>
  </div>
</header>

<div class="main">

  <!-- ── BROWSER ── -->
  <div class="browser-pane">
    <div class="pane-header">📂 <span>File Browser</span>
      <span id="file-counter" style="margin-left:auto;color:var(--accent)"></span>
    </div>
    <div class="drives-row" id="drives-row">
      <span style="font-size:10px;color:var(--muted)">Loading drives…</span>
    </div>
    <div class="breadcrumb" id="breadcrumb"></div>
    <div class="file-tree" id="file-tree">
      <div class="tree-empty">Select a drive or mount point above<br>to browse for video files.</div>
    </div>
  </div>

  <!-- ── PLAYER ── -->
  <div class="player-pane">
    <div class="video-wrap">
      <div class="placeholder" id="placeholder">
        <div class="ph-icon">▶</div>
        <div>Select a media file</div>
        <div style="font-size:10px;color:var(--muted2);margin-top:4px">Byte-Range · Seekable · LAN-direct</div>
      </div>
      <video id="player-video" preload="metadata" controls style="display:none"></video>
    </div>

    <div class="info-row">
      <span class="now-playing" id="now-playing">No file selected</span>
      <span class="tag live" id="tag-live" style="display:none">⚡ Streaming</span>
      <span class="tag" id="tag-size"></span>
      <span class="tag" id="tag-ext"></span>
    </div>

    <div class="stats-strip">
      <div class="stat-cell"><div class="stat-label">Latency</div><div class="stat-value">~0ms</div></div>
      <div class="stat-cell"><div class="stat-label">Protocol</div><div class="stat-value">HTTP/1.1</div></div>
      <div class="stat-cell"><div class="stat-label">Transfer</div><div class="stat-value">Byte-Range</div></div>
      <div class="stat-cell"><div class="stat-label">Buffer</div><div class="stat-value" id="buf-stat">IDLE</div></div>
    </div>

    <div class="controls">
      <button class="btn" id="btn-reload" onclick="reloadCurrent()" style="display:none">↺ Reload</button>
      <button class="btn" id="btn-prev" onclick="stepFile(-1)" disabled>◀ Prev</button>
      <button class="btn" id="btn-next" onclick="stepFile(1)"  disabled>Next ▶</button>
      <div class="url-group">
        <input class="url-input" id="url-input" readonly placeholder="No file selected" onclick="this.select()">
        <button class="btn primary" onclick="copyUrl()">Copy URL</button>
      </div>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── CONSTANTS ──────────────────────────────────────────────────────────────────
const SESSION_LIFETIME = <?= SESSION_LIFETIME ?>;

// ── STATE ──────────────────────────────────────────────────────────────────────
let currentPath  = '';
let currentDrive = '';
let dirFiles     = [];
let activeIndex  = -1;
let crumbs       = [];
let isAuthorized = true; // server-verified by PHP gate
let isAdmin      = false; // elevated via PIN

const player = document.getElementById('player');

// ── INIT ───────────────────────────────────────────────────────────────────────
document.getElementById('srv-addr').textContent =
  window.location.hostname + ':' + (window.location.port || '80');

document.addEventListener('keydown', globalKeydown);

// Auth verified server-side — boot immediately
loadRoots();

// ── LOGOUT ────────────────────────────────────────────────────────────────────
async function doLogout() {
  try { await fetch('?action=logout'); } catch(e) {}
  window.location.href = 'auth.php';
}

// ── ADMIN MODE ────────────────────────────────────────────────────────────────
function onAdminBtnClick() {
  if (isAdmin) {
    revokeAdmin();
  } else {
    openAdminModal();
  }
}

function openAdminModal() {
  document.getElementById('admin-modal-backdrop').classList.add('open');
  const inp = document.getElementById('admin-pin-input');
  inp.value = '';
  clearPinError();
  setTimeout(() => inp.focus(), 120);
}

function closeAdminModal() {
  document.getElementById('admin-modal-backdrop').classList.remove('open');
}

function clearPinError() {
  const inp = document.getElementById('admin-pin-input');
  const err = document.getElementById('admin-pin-error');
  inp.classList.remove('error');
  err.textContent = '';
}

async function confirmAdminPin() {
  const inp = document.getElementById('admin-pin-input');
  const btn = document.getElementById('admin-confirm-btn');
  const pin = inp.value.trim();
  if (!pin) return;

  btn.disabled = true;
  btn.textContent = 'Verifying…';

  try {
    const r = await fetch('?action=verify_admin&pin=' + encodeURIComponent(pin));
    const data = await r.json();
    if (data.ok) {
      isAdmin = true;
      closeAdminModal();
      applyAdminUI();
      toast('🛡️ Admin mode activated');
      // Refresh current directory to reveal hidden files
      if (currentPath) browsePath(currentPath);
    } else {
      showPinError('Invalid PIN — access denied');
    }
  } catch(e) {
    showPinError('Network error — try again');
  } finally {
    btn.disabled = false;
    btn.textContent = '🛡️ VERIFY PIN';
  }
}

async function revokeAdmin() {
  try { await fetch('?action=revoke_admin'); } catch(e) {}
  isAdmin = false;
  applyAdminUI();
  toast('Admin mode deactivated');
  // Refresh directory to hide dot-files again
  if (currentPath) browsePath(currentPath);
}

function showPinError(msg) {
  const inp = document.getElementById('admin-pin-input');
  const err = document.getElementById('admin-pin-error');
  inp.classList.add('error');
  err.textContent = msg;
  inp.value = '';
  setTimeout(() => inp.classList.remove('error'), 400);
}

function applyAdminUI() {
  const btnAdmin   = document.getElementById('btn-admin');
  const btnSess    = document.getElementById('btn-sessions');
  const adminBand  = document.getElementById('admin-active-band');

  if (isAdmin) {
    btnAdmin.classList.add('active');
    btnSess.style.display = '';
    adminBand.classList.add('show');
  } else {
    btnAdmin.classList.remove('active');
    btnSess.style.display = 'none';
    adminBand.classList.remove('show');
  }
}


// ── SESSION PANEL ─────────────────────────────────────────────────────────────
let sessionPanelOpen = false;

function openSessionPanel() {
  sessionPanelOpen = true;
  document.getElementById('session-panel').classList.add('open');
  document.getElementById('panel-backdrop').classList.add('open');
  loadSessions();
}

function closeSessionPanel() {
  sessionPanelOpen = false;
  document.getElementById('session-panel').classList.remove('open');
  document.getElementById('panel-backdrop').classList.remove('open');
}

function toggleSessionPanel() {
  sessionPanelOpen ? closeSessionPanel() : openSessionPanel();
}

// ── LOAD SESSIONS ─────────────────────────────────────────────────────────────
async function loadSessions() {
  const list     = document.getElementById('session-list');
  const countEl  = document.getElementById('sp-count');
  const kickAllB = document.getElementById('kick-all-btn');

  list.innerHTML = '<div class="sp-loading">Loading sessions</div>';
  kickAllB.disabled = true;

  try {
    const r    = await fetch('?action=list_sessions');
    if (r.status === 401) { closeSessionPanel(); doLogout(); return; }
    const sessions = await r.json();

    if (!sessions.length) {
      list.innerHTML = '<div class="sess-empty">No active sessions found.<br>This session may have expired.</div>';
      countEl.textContent = '';
      return;
    }

    const others = sessions.filter(s => !s.is_current);
    countEl.textContent = sessions.length + ' session' + (sessions.length !== 1 ? 's' : '') + ' active';
    kickAllB.disabled = others.length === 0;

    list.innerHTML = sessions.map(s => renderSessionCard(s)).join('');
  } catch(e) {
    list.innerHTML = '<div class="sess-empty">⚠ Failed to load sessions.</div>';
  }
}

function renderSessionCard(s) {
  const now     = Math.floor(Date.now() / 1000);
  const loginAgo   = fmtAgo(now - s.login_time);
  const activeAgo  = fmtAgo(now - s.last_activity);
  const remaining  = s.expires - now;
  const pct        = Math.max(0, Math.min(100, Math.round((remaining / SESSION_LIFETIME) * 100)));
  const expStr     = remaining > 0 ? fmtDuration(remaining) + ' left' : 'EXPIRED';

  const kickHtml = s.is_current ? '' :
    `<button class="kick-btn" id="kick-${s.sid}" onclick="kickSession('${escJs(s.sid)}')">⚡ KICK</button>`;

  return `
    <div class="sess-card ${s.is_current ? 'current' : ''}" id="sess-${escId(s.sid)}">
      <div class="sess-top">
        <span class="sess-badge ${s.is_current ? 'cur' : 'act'}">${s.is_current ? 'THIS' : 'ACTIVE'}</span>
        <span class="sess-device">${escHtml(s.device)}</span>
      </div>
      <div class="sess-meta">
        <div class="sess-meta-row">
          <span class="sess-meta-key">IP</span>
          <span class="sess-meta-val ip">${escHtml(s.ip)}</span>
        </div>
        <div class="sess-meta-row">
          <span class="sess-meta-key">Logged in</span>
          <span class="sess-meta-val">${escHtml(loginAgo)}</span>
        </div>
        <div class="sess-meta-row">
          <span class="sess-meta-key">Active</span>
          <span class="sess-meta-val">${escHtml(activeAgo)}</span>
        </div>
        <div class="sess-meta-row">
          <span class="sess-meta-key">Expires</span>
          <span class="sess-meta-val">${escHtml(expStr)}</span>
        </div>
      </div>
      <div class="sess-bar"><div class="sess-bar-fill" style="width:${pct}%"></div></div>
      ${kickHtml}
    </div>`;
}

async function kickSession(sid) {
  const btn  = document.getElementById('kick-' + sid);
  const card = document.getElementById('sess-' + sid);
  if (btn)  { btn.disabled = true; btn.textContent = 'Kicking…'; }

  try {
    const r    = await fetch('?action=kick_session&sid=' + encodeURIComponent(sid));
    const data = await r.json();
    if (data.ok) {
      if (card) {
        card.classList.add('kicked');
        setTimeout(() => { card.remove(); refreshSessionCount(); }, 380);
      }
      toast('⚡ Session kicked');
    } else {
      toast('⚠ ' + (data.error || 'Kick failed'), true);
      if (btn) { btn.disabled = false; btn.textContent = '⚡ KICK'; }
    }
  } catch(e) {
    toast('⚠ Connection error', true);
    if (btn) { btn.disabled = false; btn.textContent = '⚡ KICK'; }
  }
}

async function kickAllOthers() {
  const btn  = document.getElementById('kick-all-btn');
  btn.disabled = true;
  btn.textContent = 'Kicking…';
  try {
    const r    = await fetch('?action=list_sessions');
    const sessions = await r.json();
    const others   = sessions.filter(s => !s.is_current);
    await Promise.all(others.map(s => kickSession(s.sid)));
    btn.textContent = '⚡ KICK ALL OTHERS';
    setTimeout(loadSessions, 500);
  } catch(e) {
    toast('⚠ Error during kick all', true);
    btn.textContent = '⚡ KICK ALL OTHERS';
  }
}

function refreshSessionCount() {
  const cards   = document.querySelectorAll('.sess-card:not(.kicked)');
  const others  = document.querySelectorAll('.kick-btn:not(:disabled)');
  const countEl = document.getElementById('sp-count');
  const kickAllB= document.getElementById('kick-all-btn');
  countEl.textContent = cards.length + ' session' + (cards.length !== 1 ? 's' : '') + ' active';
  kickAllB.disabled   = others.length === 0;
}

// ── DRIVES / ROOTS ─────────────────────────────────────────────────────────────
async function loadRoots() {
  try {
    const r     = await fetch('?action=roots');
    const roots = await r.json();
    const row   = document.getElementById('drives-row');
    row.innerHTML = '';

    if (!roots.length) {
      row.innerHTML = '<span style="font-size:10px;color:var(--muted)">No accessible drives found</span>';
      return;
    }

    roots.forEach(root => {
      const btn       = document.createElement('button');
      btn.className   = 'drive-btn';
      btn.textContent = root.label;
      btn.title       = root.path;
      btn.id          = 'drive-' + root.label.replace(/[^a-z0-9]/gi, '_');
      btn.onclick     = () => browseRoot(root, btn);
      row.appendChild(btn);
    });

    const osTag = document.getElementById('os-tag');
    if      (roots[0].type === 'drive') osTag.textContent = 'WIN';
    else if (roots[0].type === 'mount') osTag.textContent = 'LINUX';
    else                                osTag.textContent = 'UNIX';

  } catch(e) {
    if (e.message && e.message.includes('401')) { doLogout(); return; }
    document.getElementById('drives-row').innerHTML =
      '<span style="font-size:10px;color:#ff7090">Failed to load drives</span>';
  }
}

function browseRoot(root, btn) {
  document.querySelectorAll('.drive-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentDrive = root.label;
  crumbs = [{ label: root.label, path: root.path }];
  browsePath(root.path);
}

// ── DIRECTORY BROWSING ────────────────────────────────────────────────────────
async function browsePath(path) {
  currentPath = path;
  renderBreadcrumb();

  const tree = document.getElementById('file-tree');
  tree.innerHTML = '<div class="tree-loading">Scanning directory</div>';

  try {
    const r    = await fetch('?action=browse&path=' + encodeURIComponent(path));
    if (r.status === 401) { doLogout(); return; }
    const data = await r.json();

    if (data.error && !data.dirs?.length && !data.files?.length) {
      tree.innerHTML = `<div class="tree-error">⚠ ${escHtml(data.error)}</div>`;
      return;
    }

    dirFiles    = data.files || [];
    activeIndex = -1;
    renderTree(data.dirs || [], dirFiles);
    updateNavButtons();
    const v = dirFiles.filter(f => f.type==='video').length;
    const a = dirFiles.filter(f => f.type==='audio').length;
    const i = dirFiles.filter(f => f.type==='image').length;
    const z = dirFiles.filter(f => f.type==='archive').length;
    document.getElementById('file-counter').textContent = `${v} V | ${a} A | ${i} I | ${z} Z`;

  } catch(e) {
    tree.innerHTML = '<div class="tree-error">⚠ Failed to read directory</div>';
  }
}

let _dirMap  = [];
let _fileMap = [];

function renderTree(dirs, files) {
  const tree = document.getElementById('file-tree');
  _dirMap  = dirs.slice();
  _fileMap = files.slice();

  if (!dirs.length && !files.length) {
    tree.innerHTML = '<div class="tree-empty">No media files or sub-folders here.</div>';
    attachTreeClicks();
    return;
  }

  let html = '';
  if (crumbs.length > 1) {
    html += `<div class="tree-item is-dir" data-action="up">
      <span class="item-icon">↑</span>
      <span class="item-name" style="color:var(--muted2)">..</span>
    </div>`;
  }

  dirs.forEach((d, i) => {
    const hideBadge = d.hidden ? '<span class="item-hidden-badge">.HIDDEN</span>' : '';
    html += `<div class="tree-item is-dir" data-action="dir" data-di="${i}">
      <span class="item-icon">${d.hidden ? '📂' : '📁'}</span>
      <span class="item-name">${escHtml(d.name)}</span>
      ${hideBadge}
    </div>`;
  });

  files.forEach((f, i) => {
    let icon = '📄';
    if (f.type === 'video')   icon = '🎬';
    if (f.type === 'audio')   icon = '🎵';
    if (f.type === 'image')   icon = '🖼️';
    if (f.type === 'archive') icon = '📦';
    if (f.type === 'dotfile') icon = '📋';
    const hideBadge = f.hidden ? '<span class="item-hidden-badge">.FILE</span>' : '';
    
    html += `<div class="tree-item is-file" id="fi-${i}" data-action="file" data-fi="${i}">
      <span class="item-icon">${icon}</span>
      <span class="item-name">${escHtml(f.name)}</span>
      ${hideBadge}
      <span class="item-ext">${escHtml(f.ext || '—')}</span>
      <span class="item-size">${escHtml(f.size_fmt)}</span>
    </div>`;
  });

  tree.innerHTML = html;
  attachTreeClicks();
}

function attachTreeClicks() {
  const tree  = document.getElementById('file-tree');
  const fresh = tree.cloneNode(true);
  tree.parentNode.replaceChild(fresh, tree);

  fresh.addEventListener('click', e => {
    const item   = e.target.closest('[data-action]');
    if (!item) return;
    const action = item.dataset.action;
    if      (action === 'up')   navigateUp();
    else if (action === 'dir')  { const d = _dirMap[parseInt(item.dataset.di, 10)]; if (d) { crumbs.push({ label: d.name, path: d.path }); browsePath(d.path); } }
    else if (action === 'file') playFile(parseInt(item.dataset.fi, 10));
  });
}

function navigateUp() {
  if (crumbs.length <= 1) return;
  crumbs.pop();
  browsePath(crumbs[crumbs.length - 1].path);
}

function renderBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  bc.innerHTML = crumbs.map((c, i) => {
    const isLast = i === crumbs.length - 1;
    return (i > 0 ? '<span class="crumb-sep">/</span>' : '')
      + `<span class="crumb" ${isLast ? '' : `data-crumb="${i}"`}>${escHtml(c.label)}</span>`;
  }).join('');

  bc.onclick = e => {
    const el = e.target.closest('[data-crumb]');
    if (!el) return;
    const idx = parseInt(el.dataset.crumb, 10);
    crumbs = crumbs.slice(0, idx + 1);
    browsePath(crumbs[idx].path);
  };
}

// ── PLAYBACK ──────────────────────────────────────────────────────────────────
function playFile(idx) {
  if (idx < 0 || idx >= dirFiles.length) return;

  if (activeIndex >= 0)
    document.getElementById('fi-' + activeIndex)?.classList.remove('active-file');

  activeIndex = idx;
  const f     = dirFiles[idx];

  document.getElementById('fi-' + idx)?.classList.add('active-file');
  document.getElementById('fi-' + idx)?.scrollIntoView({ block: 'nearest' });

  const url = '?action=stream&path=' + encodeURIComponent(f.path);

  document.getElementById('placeholder').style.display = 'none';
  
  const pv = document.getElementById('player-video');
  const mModal = document.getElementById('media-modal');
  const mImg = document.getElementById('modal-img');
  const mAud = document.getElementById('modal-audio');
  const mArc = document.getElementById('modal-archive');
  const mDl  = document.getElementById('modal-dl');
  
  pv.style.display = 'none';
  pv.pause(); pv.src = ''; pv.removeAttribute('src');

  if (window.hlsPlayer) {
    window.hlsPlayer.destroy();
    window.hlsPlayer = null;
  }
  
  if (f.type === 'video') {
    pv.style.display = 'block';
    if (f.ext === 'ts' && typeof Hls !== 'undefined' && Hls.isSupported()) {
      window.hlsPlayer = new Hls({
        maxBufferLength: 60,
        maxMaxBufferLength: 120,
      });
      const playlistUrl = '?action=hls_playlist&path=' + encodeURIComponent(f.path);
      window.hlsPlayer.loadSource(playlistUrl);
      window.hlsPlayer.attachMedia(pv);
      window.hlsPlayer.on(Hls.Events.MANIFEST_PARSED, function() {
        pv.play().catch(() => {});
      });
    } else {
      pv.src = url;
      pv.load();
      pv.play().catch(() => {});
    }
  } else if (f.type === 'dotfile' || f.type === 'other') {
    // Admin-only: treat dot-files as downloadable items
    document.getElementById('placeholder').style.display = 'flex';
    mImg.style.display = 'none';
    mAud.style.display = 'none';
    mArc.style.display = 'block';
    mAud.pause(); mAud.src = ''; mAud.removeAttribute('src');
    mImg.src = '';
    document.getElementById('modal-archive-name').textContent = f.name;
    document.getElementById('modal-archive-size').textContent = f.size_fmt;
    mDl.href = url + '&dl=1';
    mModal.classList.add('open');
  } else if (f.type === 'audio' || f.type === 'image' || f.type === 'archive') {
    document.getElementById('placeholder').style.display = 'flex'; // show placeholder in bg
    mImg.style.display = 'none';
    mAud.style.display = 'none';
    mArc.style.display = 'none';
    mAud.pause(); mAud.src = ''; mAud.removeAttribute('src');
    mImg.src = '';
    
    mDl.href = url + '&dl=1';
    
    if (f.type === 'audio') {
      mAud.style.display = 'block';
      mAud.src = url;
      mAud.load();
      mAud.play().catch(() => {});
    } else if (f.type === 'image') {
      mImg.style.display = 'block';
      mImg.src = url;
    } else if (f.type === 'archive') {
      mArc.style.display = 'block';
      document.getElementById('modal-archive-name').textContent = f.name;
      document.getElementById('modal-archive-size').textContent = f.size_fmt;
    }
    mModal.classList.add('open');
  }

  document.getElementById('now-playing').textContent = f.name;
  document.getElementById('tag-size').textContent    = f.size_fmt;
  document.getElementById('tag-ext').textContent     = f.ext.toUpperCase();
  document.getElementById('tag-live').style.display  = 'inline';
  document.getElementById('url-input').value         = window.location.origin + window.location.pathname + url;
  document.getElementById('btn-reload').style.display = 'inline-flex';
  document.getElementById('buf-stat').textContent    = 'LIVE';
  updateNavButtons();
}

function stepFile(dir) {
  if (activeIndex < 0) return;
  const currentType = dirFiles[activeIndex].type;
  let next = activeIndex + dir;
  while (next >= 0 && next < dirFiles.length) {
    if (dirFiles[next].type === currentType) {
      playFile(next);
      return;
    }
    next += dir;
  }
  toast(dir < 0 ? '⬅ First ' + currentType : '➡ Last ' + currentType);
}

function reloadCurrent() { if (activeIndex >= 0) playFile(activeIndex); }

function updateNavButtons() {
  document.getElementById('btn-prev').disabled = activeIndex <= 0;
  document.getElementById('btn-next').disabled = activeIndex < 0 || activeIndex >= dirFiles.length - 1;
}

// ── PLAYER EVENTS ─────────────────────────────────────────────────────────────
function attachEvents(p) {
  if (!p) return;
  p.addEventListener('waiting', () => setBuf('BUFFERING…'));
  p.addEventListener('playing', () => setBuf('LIVE'));
  p.addEventListener('ended',   () => { setBuf('ENDED'); stepFile(1); });
  p.addEventListener('error',   () => setBuf('ERROR ⚠'));
  p.addEventListener('stalled', () => setBuf('STALLED'));
  p.addEventListener('canplay', () => setBuf('READY'));
}
attachEvents(document.getElementById('player-video'));
attachEvents(document.getElementById('modal-audio'));
function setBuf(s) { document.getElementById('buf-stat').textContent = s; }

// ── SWIPE GESTURES (MODAL) ────────────────────────────────────────────────────
let touchStartX = 0;
const mediaModal = document.getElementById('media-modal');
mediaModal.addEventListener('touchstart', e => {
  touchStartX = e.changedTouches[0].screenX;
}, {passive: true});
mediaModal.addEventListener('touchend', e => {
  const touchEndX = e.changedTouches[0].screenX;
  if (touchEndX < touchStartX - 50) stepFile(1);  // swipe left -> next
  if (touchEndX > touchStartX + 50) stepFile(-1); // swipe right -> prev
}, {passive: true});

function closeMediaModal() {
  document.getElementById('media-modal').classList.remove('open');
  const ma = document.getElementById('modal-audio');
  ma.pause(); ma.src = ''; ma.removeAttribute('src');
  document.getElementById('modal-img').src = '';
}

// ── COPY URL ──────────────────────────────────────────────────────────────────
function copyUrl() {
  const u = document.getElementById('url-input').value;
  if (!u) { toast('No file selected'); return; }
  navigator.clipboard.writeText(u).then(() => toast('✓ Stream URL copied!'));
}

// ── KEYBOARD ──────────────────────────────────────────────────────────────────
function globalKeydown(e) {
  // Ctrl+Shift+K — session manager (admins only)
  if (e.ctrlKey && e.shiftKey && e.key === 'K') {
    e.preventDefault();
    if (isAdmin) toggleSessionPanel();
    return;
  }

  // Block shortcuts when typing in any input
  if (e.target.tagName === 'INPUT') return;

  // Auth overlay active — ignore player shortcuts
  if (!isAuthorized) return;

  if (e.key === 'ArrowLeft')  stepFile(-1);
  if (e.key === 'ArrowRight') stepFile(1);
  if (e.key === ' ') {
    e.preventDefault();
    const pv = document.getElementById('player-video');
    const ma = document.getElementById('modal-audio');
    const p = (pv && pv.style.display === 'block') ? pv : ((document.getElementById('media-modal').classList.contains('open') && ma.style.display === 'block') ? ma : null);
    if (p) p.paused ? p.play() : p.pause();
  }
  if (e.key === 'Backspace' && document.activeElement.tagName !== 'INPUT') navigateUp();
  if (e.key === 'Escape') {
    if (sessionPanelOpen) closeSessionPanel();
    if (document.getElementById('media-modal').classList.contains('open')) closeMediaModal();
  }
}

// ── UTILS ─────────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escJs(s) { return String(s).replace(/['"\\]/g, c => '\\' + c); }
function escId(s) { return String(s).replace(/[^a-zA-Z0-9_-]/g, '_'); }

function fmtAgo(secs) {
  if (secs < 5)    return 'just now';
  if (secs < 60)   return secs + 's ago';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
  return Math.floor(secs / 3600) + 'h ago';
}

function fmtDuration(secs) {
  if (secs < 60)   return secs + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h + 'h ' + (m ? m + 'm' : '');
}

let toastTimer;
function toast(msg, isErr = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className   = 'on' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = '', 2600);
}
</script>
</body>
</html>
<?php
  exit;
}