<?php
/**
 * VULNERABILITY: Insecure Deserialization (CWE-502)
 *
 * User preferences are stored, serialized, in a client-side cookie and
 * restored with unserialize() on every request. Because the app
 * autoloads/includes classes with dangerous magic methods
 * (see includes/classes.php: Logger::__destruct), an attacker can
 * replace the cookie with a crafted serialized object of their own
 * choosing to trigger unintended behavior (a "gadget chain") -
 * this is the general pattern behind most PHP deserialization RCEs,
 * including the ones currently making the rounds in popular PHP
 * frameworks/plugins.
 *
 * Exploit example: an attacker crafts and sets the "prefs" cookie to
 * a serialized Logger object with ->logFile pointing inside the
 * webroot and ->logMessage containing a PHP webshell payload, turning
 * an arbitrary-file-write primitive into RCE on the next request to
 * the written file.
 *
 * FIX (for the agent to apply):
 *   - Never call unserialize() on data that crosses a trust boundary
 *     (cookies, GET/POST, uploaded files, etc.).
 *   - Use json_encode()/json_decode() for structured data you need to
 *     round-trip through the client - it carries no executable
 *     "magic method" semantics.
 *   - If unserialize() is unavoidable, use the `allowed_classes` option
 *     (PHP 7+) to restrict it to known-safe classes.
 */

require_once __DIR__ . '/includes/classes.php';

$prefs = new UserPreferences();

if (isset($_COOKIE['prefs'])) {
    // VULNERABLE: unserializing untrusted, client-controlled cookie data
    $restored = unserialize($_COOKIE['prefs']);
    if ($restored instanceof UserPreferences) {
        $prefs = $restored;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $prefs->theme = $_POST['theme'] ?? $prefs->theme;
    $prefs->language = $_POST['language'] ?? $prefs->language;
    setcookie('prefs', serialize($prefs), time() + 3600, '/');
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Saved Preferences</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; color: #222; }
        select, button { padding: 6px 10px; }
        a { display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Saved Preferences</h1>
    <p>Tema actual: <strong><?php echo htmlspecialchars($prefs->theme); ?></strong> &middot;
       Idioma: <strong><?php echo htmlspecialchars($prefs->language); ?></strong></p>

    <form method="post">
        <select name="theme">
            <option value="light" <?php echo $prefs->theme === 'light' ? 'selected' : ''; ?>>Light</option>
            <option value="dark" <?php echo $prefs->theme === 'dark' ? 'selected' : ''; ?>>Dark</option>
        </select>
        <select name="language">
            <option value="es" <?php echo $prefs->language === 'es' ? 'selected' : ''; ?>>Español</option>
            <option value="en" <?php echo $prefs->language === 'en' ? 'selected' : ''; ?>>English</option>
        </select>
        <button type="submit">Guardar</button>
    </form>

    <a href="index.php">&larr; Volver</a>
</body>
</html>
