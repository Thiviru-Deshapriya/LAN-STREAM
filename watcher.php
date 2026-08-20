<?php
/**
 * LAN Stream — Foreground Console Log Watcher (watcher.php)
 * ─────────────────────────────────────────────────────────────────────────────
 * Tails both the Apache access log and the LAN Stream system log, formatting
 * and outputting request logs and system status events to the console in real-time.
 */

// Enable VT100 colors on Windows
if (function_exists('sapi_windows_vt100_support')) {
    @sapi_windows_vt100_support(STDOUT, true);
}

// Color constants
define('C_RESET',   "\033[0m");
define('C_BOLD',    "\033[1m");
define('C_GRAY',    "\033[90m");
define('C_GREEN',   "\033[32m");
define('C_CYAN',    "\033[36m");
define('C_YELLOW',  "\033[33m");
define('C_RED',     "\033[31m");

$stream_log    = __DIR__ . '/logs/stream.log';
$apache_access = 'C:/xampp/apache/logs/access.log';

// Ensure the files exist so we can open them
if (!file_exists($stream_log)) {
    @mkdir(dirname($stream_log), 0755, true);
    @touch($stream_log);
}
if (!file_exists($apache_access)) {
    @mkdir(dirname($apache_access), 0755, true);
    @touch($apache_access);
}

// Open log files and seek to the end (only watch new logs)
$fp_stream = @fopen($stream_log, 'r');
if ($fp_stream) fseek($fp_stream, 0, SEEK_END);

$fp_apache = @fopen($apache_access, 'r');
if ($fp_apache) fseek($fp_apache, 0, SEEK_END);

echo C_CYAN . C_BOLD . "  LAN Stream v2 Log Monitor Started." . C_RESET . PHP_EOL;
echo C_GRAY . "  Tailing Apache requests and system logs... [Press Ctrl+C to Stop]" . C_RESET . PHP_EOL;
echo C_GRAY . "  -----------------------------------------------------------------" . C_RESET . PHP_EOL . PHP_EOL;

while (true) {
    // 1. Tail Stream Log (System status logs like PINs, logouts, kicks)
    if ($fp_stream) {
        $line = fgets($fp_stream);
        if ($line !== false && $line !== "") {
            echo $line; // stream log lines already have formatting & newlines
        }
    }

    // 2. Tail Apache Access Log (HTTP request traffic)
    if ($fp_apache) {
        $line = fgets($fp_apache);
        if ($line !== false && $line !== "") {
            // Parse Apache common log format:
            // 192.168.1.2 - - [08/Jun/2026:06:23:09 +0530] "GET /auth.php HTTP/1.1" 200 4828
            $pattern = '/^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\S+)/';
            if (preg_match($pattern, trim($line), $m)) {
                $ip     = $m[1];
                $time   = $m[2];
                $method = $m[3];
                $uri    = $m[4];
                $status = $m[5];
                
                // Format timestamp to match PHP built-in server style:
                // [Mon Jun  8 06:23:09 2026]
                $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $time);
                $formatted_time = $dt ? $dt->format('D M j H:i:s Y') : $time;

                // Colorize status code
                $status_color = C_GREEN;
                if ($status >= 400) $status_color = C_RED;
                elseif ($status >= 300) $status_color = C_YELLOW;

                // Colorize static asset requests so they are less distracting
                $is_static = preg_match('/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2)$/', parse_url($uri, PHP_URL_PATH));
                
                if ($is_static) {
                    // Dimmed gray for static resources
                    echo C_GRAY . "[{$formatted_time}] {$ip} [{$status}]: {$method} {$uri}" . C_RESET . PHP_EOL;
                } else {
                    // Normal output
                    echo "[{$formatted_time}] {$ip} [{$status_color}{$status}" . C_RESET . "]: {$method} " . C_CYAN . $uri . C_RESET . PHP_EOL;
                }
            }
        }
    }

    usleep(50000); // 50ms check interval for high responsiveness
}
