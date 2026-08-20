<?php
/**
 * LAN Stream — CLI Admin Session Manager (admin.php)
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides a terminal-based interface on the server PC to view active network
 * connections/sessions, show pending PIN requests, and monitor system activity logs.
 */

// Enable VT100 color support on Windows
if (function_exists('sapi_windows_vt100_support')) {
    @sapi_windows_vt100_support(STDOUT, true);
}

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
define('SESSION_REGISTRY', __DIR__ . '/data/sessions.json');
define('SESSION_DIR',      __DIR__ . '/data/sess');
define('PIN_QUEUE_FILE',   __DIR__ . '/data/pin_queue.json');
define('LOG_FILE',         __DIR__ . '/logs/stream.log');
define('SESSION_LIFETIME', 86400);

// Color Helpers
define('C_RESET',   "\033[0m");
define('C_BOLD',    "\033[1m");
define('C_RED',     "\033[31m");
define('C_GREEN',   "\033[32m");
define('C_YELLOW',  "\033[33m");
define('C_BLUE',    "\033[34m");
define('C_MAGENTA', "\033[35m");
define('C_CYAN',    "\033[36m");
define('C_GRAY',    "\033[90m");

// ─── REGISTRY HELPERS ─────────────────────────────────────────────────────────
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

function registry_remove(string $sid): void {
    $s = registry_load();
    unset($s[$sid]);
    registry_save($s);
}

function registry_get_all(): array {
    $s = registry_load();
    $now = time();
    $clean = [];
    foreach ($s as $sid => $info) {
        if (($info['expires'] ?? 0) > $now) $clean[$sid] = $info;
    }
    if (count($clean) !== count($s)) registry_save($clean);
    return array_values($clean);
}

function destroy_session_by_id(string $sid): bool {
    if (!preg_match('/^[a-zA-Z0-9,\-]{10,128}$/', $sid)) return false;
    $file = SESSION_DIR . DIRECTORY_SEPARATOR . 'sess_' . $sid;
    if (file_exists($file)) @unlink($file);
    registry_remove($sid);
    return true;
}

// ─── PIN QUEUE HELPERS ────────────────────────────────────────────────────────
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

function get_pending_pins(): array {
    $queue = pin_queue_load();
    $now   = time();
    $pending = [];
    foreach ($queue as $ip => $entry) {
        if (($entry['expires_at'] ?? 0) > $now && !($entry['used'] ?? false)) {
            $pending[] = $entry;
        }
    }
    return $pending;
}

// ─── LOG HELPERS ──────────────────────────────────────────────────────────────
function get_recent_events(int $limit = 4): array {
    if (!file_exists(LOG_FILE)) return [];
    
    $fp = @fopen(LOG_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $size = filesize(LOG_FILE);
    $read_size = min($size, 4096); // read last 4KB
    if ($read_size > 0) {
        fseek($fp, -$read_size, SEEK_END);
        $data = fread($fp, $read_size);
    } else {
        $data = '';
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    
    if (empty($data)) return [];
    
    $lines = explode("\n", trim($data));
    $lines = array_filter(array_map('trim', $lines));
    $recent = array_slice($lines, -$limit);
    
    $events = [];
    foreach ($recent as $line) {
        if (preg_match('/^\[(.*?)\] \[(.*?)\] (.*)$/', $line, $m)) {
            $events[] = [
                'time' => date('H:i:s', strtotime($m[1])),
                'ip'   => $m[2],
                'msg'  => $m[3],
            ];
        }
    }
    return $events;
}

function clean_len(string $str): int {
    return strlen(preg_replace('/\033\[[0-9;]*m/', '', $str));
}

// ─── UTILITIES ────────────────────────────────────────────────────────────────
function parse_ua(string $ua): string {
    if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) return 'iOS';
    if (str_contains($ua, 'Android'))  return 'Android';
    if (str_contains($ua, 'Windows'))  return 'Windows';
    if (str_contains($ua, 'Macintosh')) return 'Mac';
    if (str_contains($ua, 'Linux'))    return 'Linux';
    if (str_contains($ua, 'TV') || str_contains($ua, 'Smart')) return 'TV';
    return 'Browser';
}

function fmtAgo(int $secs): string {
    if ($secs < 5)    return 'just now';
    if ($secs < 60)   return $secs . 's ago';
    if ($secs < 3600) return floor($secs / 60) . 'm ago';
    return floor($secs / 3600) . 'h ago';
}

function fmtDuration(int $secs): string {
    if ($secs < 60)   return $secs . 's';
    if ($secs < 3600) return floor($secs / 60) . 'm';
    $h = floor($secs / 3600);
    $m = floor(($secs % 3600) / 60);
    return $h . 'h' . ($m ? ' ' . $m . 'm' : '');
}

function clear_screen(): void {
    echo "\033[2J\033[H";
}

// ─── MAIN PROGRAM LOOP ────────────────────────────────────────────────────────
$is_win = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

while (true) {
    clear_screen();

    echo C_CYAN . "  +--------------------------------------------------+" . C_RESET . "\n";
    echo C_CYAN . "  |" . C_BOLD . C_MAGENTA . "            LAN Stream Session Manager            " . C_RESET . C_CYAN . "|" . C_RESET . "\n";
    echo C_CYAN . "  +--------------------------------------------------+" . C_RESET . "\n\n";

    // ── PENDING PINS ──────────────────────────────────────────────────────────
    $pending_pins = get_pending_pins();
    if (!empty($pending_pins)) {
        echo "  " . C_BOLD . C_YELLOW . "+--------------------------------------------------+" . C_RESET . "\n";
        echo "  " . C_BOLD . C_YELLOW . "|             PENDING PIN REQUESTS (LAN)           |" . C_RESET . "\n";
        echo "  " . C_BOLD . C_YELLOW . "+--------------------------------------------------+" . C_RESET . "\n";
        $now = time();
        foreach ($pending_pins as $p) {
            $rem = max(0, $p['expires_at'] - $now);
            $rem_str = fmtDuration($rem);
            printf(
                "  " . C_BOLD . C_YELLOW . "| " . C_RESET . "Device: %-15s | PIN: " . C_BOLD . C_GREEN . "%-6s" . C_RESET . " (%-6s left) " . C_BOLD . C_YELLOW . "|\n" . C_RESET,
                $p['ip'],
                $p['pin'],
                $rem_str
            );
        }
        echo "  " . C_BOLD . C_YELLOW . "+--------------------------------------------------+" . C_RESET . "\n\n";
    }

    // ── ACTIVE SESSIONS ───────────────────────────────────────────────────────
    $sessions = registry_get_all();

    if (empty($sessions)) {
        echo "  " . C_GRAY . "No active user sessions currently connected." . C_RESET . "\n\n";
    } else {
        printf(
            "  " . C_BOLD . "%-4s | %-15s | %-10s | %-12s | %-10s" . C_RESET . "\n",
            "Idx", "IP Address", "Device", "Last Active", "Time Left"
        );
        echo "  -----+-----------------+------------+--------------+-----------\n";

        $now = time();
        foreach ($sessions as $index => $s) {
            $idx = $index + 1;
            $ip = $s['ip'] ?? 'unknown';
            $device = parse_ua($s['ua'] ?? '');
            $active_ago = isset($s['last_activity']) ? fmtAgo($now - $s['last_activity']) : 'unknown';
            $time_left = isset($s['expires']) ? ($s['expires'] - $now) : 0;
            $time_left_str = $time_left > 0 ? fmtDuration($time_left) : 'expired';

            // Device-specific coloring
            $dev_color = C_RESET;
            if ($device === 'Windows' || $device === 'Mac') $dev_color = C_CYAN;
            elseif ($device === 'iOS' || $device === 'Android') $dev_color = C_GREEN;
            elseif ($device === 'TV') $dev_color = C_YELLOW;

            // Highlight recent activity
            $act_color = C_RESET;
            if (isset($s['last_activity']) && ($now - $s['last_activity']) < 30) {
                $act_color = C_GREEN . C_BOLD;
            } else {
                $act_color = C_GRAY;
            }

            printf(
                "  " . C_CYAN . "[%2d]" . C_RESET . " | %-15s | %s%-10s%s | %s%-12s%s | " . C_YELLOW . "%-10s" . C_RESET . "\n",
                $idx,
                $ip,
                $dev_color, $device, C_RESET,
                $act_color, $active_ago, C_RESET,
                $time_left_str
            );
        }
        echo "\n";
    }

    // ── RECENT SYSTEM LOGS ────────────────────────────────────────────────────
    $events = get_recent_events(4);
    if (!empty($events)) {
        echo "  " . C_BOLD . C_CYAN . "+--------------------------------------------------+" . C_RESET . "\n";
        echo "  " . C_BOLD . C_CYAN . "|                 RECENT SYSTEM ACTIVITY           |" . C_RESET . "\n";
        echo "  " . C_BOLD . C_CYAN . "+--------------------------------------------------+" . C_RESET . "\n";
        foreach ($events as $e) {
            $msg = $e['msg'];
            
            if (str_contains($msg, 'PIN GENERATED')) {
                if (preg_match('/pin=(\d+)/', $msg, $pm)) {
                    $msg_fmt = "Access requested. PIN " . C_BOLD . C_GREEN . $pm[1] . C_RESET . " generated.";
                } else {
                    $msg_fmt = "Access requested. PIN generated.";
                }
            } elseif (str_contains($msg, 'AUTH OK')) {
                $msg_fmt = C_GREEN . "Device successfully connected (Authorized)." . C_RESET;
            } elseif (str_contains($msg, 'AUTH FAIL')) {
                $msg_fmt = C_RED . "Access denied: Incorrect/expired PIN." . C_RESET;
            } elseif (str_contains($msg, 'LOGOUT')) {
                $msg_fmt = C_YELLOW . "Device disconnected." . C_RESET;
            } elseif (str_contains($msg, 'KICK')) {
                $msg_fmt = C_RED . "Session kicked by administrator." . C_RESET;
            } elseif (str_contains($msg, 'STREAM')) {
                $file = '';
                if (preg_match('/STREAM (.*?) \|/', $msg, $fm)) {
                    $file = basename($fm[1]);
                    if (strlen($file) > 18) $file = substr($file, 0, 15) . '...';
                }
                $msg_fmt = "Started streaming: " . C_CYAN . $file . C_RESET;
            } elseif (str_contains($msg, 'DONE')) {
                $file = '';
                if (preg_match('/DONE (.*?) \|/', $msg, $fm)) {
                    $file = basename($fm[1]);
                    if (strlen($file) > 18) $file = substr($file, 0, 15) . '...';
                }
                $msg_fmt = "Finished streaming: " . C_GRAY . $file . C_RESET;
            } else {
                $msg_fmt = $msg;
            }
            
            // Format time and IP block
            $ip_str = $e['ip'] === 'cli' ? 'server' : $e['ip'];
            $prefix_raw = sprintf("%s [%s] ", $e['time'], $ip_str);
            $total_width = strlen($prefix_raw) + clean_len($msg_fmt);
            $spaces = max(0, 48 - $total_width);
            
            echo "  " . C_CYAN . "| " . C_RESET . C_GRAY . $e['time'] . C_RESET 
                . " [" . C_BLUE . $ip_str . C_RESET . "] " 
                . $msg_fmt . str_repeat(' ', $spaces) . C_CYAN . " |" . C_RESET . "\n";
        }
        echo "  " . C_BOLD . C_CYAN . "+--------------------------------------------------+" . C_RESET . "\n\n";
    }

    echo C_CYAN . "  --------------------------------------------------" . C_RESET . "\n";
    echo "  " . C_BOLD . "[Auto-refreshes every 2s] or press:" . C_RESET . "\n";
    if (!empty($sessions)) {
        echo "  " . C_BOLD . "[1-" . min(9, count($sessions)) . "]" . C_RESET . " to Kick Session\n";
        echo "  " . C_BOLD . "[K]" . C_RESET . " to Kick ALL sessions\n";
    }
    echo "  " . C_BOLD . "[Q]" . C_RESET . " to Quit\n";
    echo C_CYAN . "  --------------------------------------------------" . C_RESET . "\n";
    echo "  Waiting for input... ";

    $choice = 'r';

    if ($is_win) {
        $exit_code = 0;
        system('choice /C qk123456789r /N /T 2 /D r >NUL 2>NUL', $exit_code);

        if ($exit_code === 1) {
            $choice = 'q';
        } elseif ($exit_code === 2) {
            $choice = 'k';
        } elseif ($exit_code >= 3 && $exit_code <= 11) {
            $choice = (string)($exit_code - 2); // '1' - '9'
        } else {
            $choice = 'r';
        }
    } else {
        $input = trim(fgets(STDIN));
        $choice = strtolower($input);
        if ($choice === '') $choice = 'r';
    }

    if ($choice === 'q') {
        echo "\n\n  Exiting Session Manager...\n";
        sleep(1);
        exit;
    }

    if ($choice === 'k') {
        if (!empty($sessions)) {
            echo "\n\n  " . C_RED . "Are you sure you want to kick ALL active sessions? (y/n): " . C_RESET;
            $confirm = trim(fgets(STDIN));
            if (strtolower($confirm) === 'y') {
                foreach ($sessions as $s) {
                    destroy_session_by_id($s['sid']);
                }
                echo "\n  " . C_GREEN . "All sessions kicked successfully!" . C_RESET . "\n";
                sleep(1);
            }
        }
        continue;
    }

    if (is_numeric($choice)) {
        $idx = (int)$choice - 1; // 0 to 8
        if (isset($sessions[$idx])) {
            $s = $sessions[$idx];
            echo "\n\n  Kicking session for IP " . C_YELLOW . ($s['ip'] ?? 'unknown') . C_RESET . "... ";
            if (destroy_session_by_id($s['sid'])) {
                echo C_GREEN . "Success!" . C_RESET . "\n";
            } else {
                echo C_RED . "Failed!" . C_RESET . "\n";
            }
            sleep(1);
        } else {
            echo "\n\n  " . C_RED . "Invalid session index!" . C_RESET . "\n";
            sleep(1);
        }
        continue;
    }
}
