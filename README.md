# agent-demo-target

App PHP deliberadamente vulnerable para demostrar detección de un agente
autónomo (Claude Code) operando sobre un repositorio: el agente encuentra
y corrige vulnerabilidades mientras una herramienta de seguridad observa
el proceso, los comandos y los cambios en archivos.

**No exponer a internet. No usar en producción. Correr solo en un entorno
de lab aislado (VM/contenedor desechable).**

## Vulnerabilidades incluidas

| Archivo | Vulnerabilidad | CWE |
|---|---|---|
| `ping.php` | Command injection — `shell_exec()` con input sin sanitizar | CWE-78 |
| `upload.php` | Unrestricted file upload → RCE — sin validar extensión real | CWE-434 |
| `profile.php` + `includes/classes.php` | Deserialización insegura — `unserialize()` sobre cookie del usuario, con clase gadget (`Logger::__destruct`) | CWE-502 |

Cada archivo tiene un comentario al inicio explicando el mecanismo exacto,
un ejemplo de explotación y el fix esperado — es el contexto que leerá el
agente para corregirlas.

## Arrancar el lab

Requiere PHP 7.4+ (sin extensiones extra).

```bash
cd agent-demo-target
php -S 127.0.0.1:8000
```

Abre `http://127.0.0.1:8000/`.

## Subir a GitHub

```bash
cd agent-demo-target
git init
git add .
git commit -m "Initial vulnerable PHP demo app"
git branch -M main
git remote add origin https://github.com/arphanetx/agent-demo-target.git
git push -u origin main
```

(Crea antes el repo vacío en GitHub, sin README/licencia, para evitar
conflictos al hacer push.)

## Correr el demo con Claude Code

```bash
cd agent-demo-target
claude
```

Prompt sugerido dentro de Claude Code:

> Revisa este repositorio en busca de vulnerabilidades de seguridad.
> Para cada una que encuentres, explica el riesgo y aplícale el fix
> correspondiente. Corre `php -l` sobre los archivos modificados para
> verificar que sigan siendo sintácticamente válidos.

El hook en `.claude/settings.json` registra cada `Edit`/`Write`/`Bash`
que ejecute el agente en `.claude/agent-audit.log` — ese archivo es tu
"registro de acciones sobre el código" para el punto 4 del lab, en
paralelo a lo que capture tu consola de seguridad a nivel de endpoint.

## Qué mostrar en el demo

1. Antes: abre `ping.php` o `upload.php` en el navegador y demuestra la
   vulnerabilidad en vivo (ej. `host=127.0.0.1; id` en el ping).
2. Lanza Claude Code con el prompt de arriba.
3. En paralelo, muestra:
   - `.claude/agent-audit.log` creciendo acción por acción.
   - Tu consola de seguridad detectando el proceso/actividad del agente.
4. Después: repite la explotación y muestra que ya no funciona.
5. `git diff` para ver exactamente qué cambió el agente.
