<?php
/**
 * LAN Stream — Apache Configuration Setup Script (apache_setup.php)
 * ─────────────────────────────────────────────────────────────────────────────
 * Locates the XAMPP Apache configuration file and injects the Virtual Host block
 * on port 8888, pointing to the current project directory. Self-updates if the path changes.
 * Automatically loads the mod_xsendfile module and discovers all active Windows drives.
 */

$proj_dir = str_replace('\\', '/', realpath(__DIR__));
$apache_conf = 'C:/xampp/apache/conf/httpd.conf';

if (!file_exists($apache_conf)) {
    fwrite(STDERR, "Error: Apache configuration not found at {$apache_conf}\n");
    fwrite(STDERR, "Please ensure XAMPP is installed in C:\\xampp\\\n");
    exit(1);
}

$content = file_get_contents($apache_conf);
if ($content === false) {
    fwrite(STDERR, "Error: Cannot read Apache configuration.\n");
    exit(1);
}

// ── DISCOVER ACTIVE SYSTEM DRIVES ─────────────────────────────────────────────
$xsendfile_paths = "";
if (PHP_OS_FAMILY === 'Windows') {
    foreach (range('A', 'Z') as $letter) {
        $drive = $letter . ':/';
        if (is_dir($letter . ':\\')) {
            $xsendfile_paths .= "        XSendFilePath \"{$drive}\"\n";
        }
    }
} else {
    $xsendfile_paths = "        XSendFilePath \"/\"\n";
}

// ── GENERATE VHOST BLOCK ──────────────────────────────────────────────────────
$vhost_block = "\n"
    . "# === LAN STREAM CONFIGURATION START ===\n"
    . "LoadModule xsendfile_module modules/mod_xsendfile.so\n"
    . "Listen 8888\n"
    . "<VirtualHost *:8888>\n"
    . "    DocumentRoot \"{$proj_dir}\"\n"
    . "    <Directory \"{$proj_dir}\">\n"
    . "        Options Indexes FollowSymLinks\n"
    . "        AllowOverride All\n"
    . "        Require all granted\n"
    . "        EnableSendfile Off\n"
    . "    </Directory>\n"
    . "    \n"
    . "    # Support X-Sendfile offloading if module is loaded\n"
    . "    <IfModule xsendfile_module>\n"
    . "        XSendFile On\n"
    . $xsendfile_paths
    . "    </IfModule>\n"
    . "</VirtualHost>\n"
    . "# === LAN STREAM CONFIGURATION END ===\n";

// ── STRIP EXISTING BLOCK ──────────────────────────────────────────────────────
$pattern = '/# === LAN STREAM CONFIGURATION START ===.*?# === LAN STREAM CONFIGURATION END ===/s';
$content = preg_replace($pattern, '', $content);

// ── APPEND NEW BLOCK ──────────────────────────────────────────────────────────
$content = rtrim($content) . $vhost_block;

// Write back
if (file_put_contents($apache_conf, $content) === false) {
    fwrite(STDERR, "Error: Cannot write to Apache configuration. Run as Administrator if needed.\n");
    exit(1);
}

echo "Apache Virtual Host configured successfully on port 8888!\n";
echo "DocumentRoot: {$proj_dir}\n";
echo "Configured drive paths:\n" . trim(str_replace('        ', '  - ', $xsendfile_paths)) . "\n";
