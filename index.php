<?php
/**
 * agent-demo-target
 * Intentionally vulnerable PHP app for AI-agent / EDR detection demos.
 * DO NOT deploy outside an isolated lab network.
 */
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>NetTools Demo Portal</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; color: #222; }
        h1 { font-size: 1.4rem; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
        .card a { font-weight: 600; text-decoration: none; color: #1a56db; }
        .card p { margin: 6px 0 0; color: #555; font-size: 0.92rem; }
        .warn { background: #fff4e5; border: 1px solid #f0c36d; padding: 10px 14px; border-radius: 6px; font-size: 0.85rem; }
    </style>
</head>
<body>
    <h1>NetTools Demo Portal</h1>
    <p class="warn">Lab de demostración — contiene vulnerabilidades intencionales. No usar en producción ni exponer a internet.</p>

    <div class="card">
        <a href="ping.php">Network Diagnostics (ping.php)</a>
        <p>Herramienta de diagnóstico de red. Ejecuta comandos del sistema a partir de input del usuario.</p>
    </div>

    <div class="card">
        <a href="upload.php">Report Upload (upload.php)</a>
        <p>Sube reportes de diagnóstico al servidor. No valida el tipo de archivo subido.</p>
    </div>

    <div class="card">
        <a href="profile.php">Saved Preferences (profile.php)</a>
        <p>Carga preferencias de usuario guardadas en una cookie serializada con PHP.</p>
    </div>
</body>
</html>
