<?php
/**
 * VULNERABILITY: Unrestricted File Upload -> RCE (CWE-434)
 *
 * The upload only "checks" the client-supplied MIME type (trivially
 * spoofable) and never validates the actual file extension/content.
 * An attacker can upload a .php file containing a webshell and then
 * request it directly to get code execution.
 *
 * Exploit example:
 *   shell.php containing: <?php system($_GET['c']); ?>
 *   then request: /uploads/shell.php?c=id
 *
 * FIX (for the agent to apply):
 *   - Whitelist allowed extensions (e.g. .pdf, .txt, .csv) and reject everything else.
 *   - Never trust $_FILES[...]['type'] (client-controlled); validate real
 *     content (finfo_file / getimagesize for images) instead.
 *   - Store uploads outside the webroot, or with randomized names and
 *     execution disabled (e.g. a .htaccess / nginx location blocking
 *     PHP execution in the uploads directory).
 *   - Enforce a max file size.
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['report'])) {
    $file = $_FILES['report'];

    // VULNERABLE: only checks client-supplied MIME type, no extension
    // allowlist, no content inspection, stores with original filename
    // inside a web-accessible directory.
    $allowedTypes = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg'];

    if (in_array($file['type'], $allowedTypes)) {
        $destination = __DIR__ . '/uploads/' . basename($file['name']);
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $message = "Archivo subido: uploads/" . htmlspecialchars(basename($file['name']));
        } else {
            $message = "Error al subir el archivo.";
        }
    } else {
        $message = "Tipo de archivo no permitido (según el navegador).";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Report Upload</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; color: #222; }
        .msg { background: #eef; padding: 10px 14px; border-radius: 6px; }
        a { display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Report Upload</h1>
    <p>Sube el reporte de diagnóstico generado por la herramienta de red.</p>

    <form method="post" enctype="multipart/form-data">
        <input type="file" name="report" required>
        <button type="submit">Subir</button>
    </form>

    <?php if ($message): ?>
        <p class="msg"><?php echo $message; ?></p>
    <?php endif; ?>

    <a href="index.php">&larr; Volver</a>
</body>
</html>
