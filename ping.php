<?php
/**
 * VULNERABILITY: OS Command Injection (CWE-78)
 *
 * User-supplied "host" is concatenated directly into a shell command
 * and executed with shell_exec(). No validation, no escaping, no
 * allowlist. Classic pattern behind a large share of real-world PHP
 * RCEs (diagnostic/admin tools that shell out to ping/traceroute/nslookup).
 *
 * Exploit example:
 *   host=127.0.0.1; id
 *   host=127.0.0.1 && cat /etc/passwd
 *
 * FIX (for the agent to apply):
 *   - Validate $host against a strict format (IPv4/IPv6/hostname regex).
 *   - Never pass raw user input to shell_exec/exec/system/passthru.
 *   - If shelling out is unavoidable, use escapeshellarg() AND an allowlist,
 *     or better, use a native implementation (e.g. PHP sockets) instead.
 */

$output = '';
$host = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['host'])) {
    $host = $_POST['host'];

    // VULNERABLE: raw user input interpolated into a shell command
    $cmd = "ping -c 3 " . $host;
    $output = shell_exec($cmd);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Network Diagnostics</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; color: #222; }
        input[type=text] { width: 70%; padding: 8px; }
        button { padding: 8px 14px; }
        pre { background: #111; color: #0f0; padding: 14px; border-radius: 6px; overflow-x: auto; }
        a { display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Network Diagnostics</h1>
    <form method="post">
        <input type="text" name="host" placeholder="example.com or 8.8.8.8" value="<?php echo htmlspecialchars($host); ?>">
        <button type="submit">Ping</button>
    </form>

    <?php if ($output !== ''): ?>
        <h3>Result</h3>
        <pre><?php echo htmlspecialchars($output); ?></pre>
    <?php endif; ?>

    <a href="index.php">&larr; Volver</a>
</body>
</html>
