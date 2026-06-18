# Sincronizar Admin Nuevo

Si creaste un usuario admin nuevo en tu SQLite local, ese cambio no viaja por Git porque `instance/pos_v2.db` esta ignorada.

## Opcion recomendada para Render

1. En el servicio web de Render, agrega `BOOTSTRAP_ADMIN_USERNAME`.
2. Agrega `BOOTSTRAP_ADMIN_PASSWORD`.
3. Guarda los cambios.
4. Haz un redeploy del servicio.

Al arrancar, la app crea ese admin solo si todavia no existe y no modifica admins previos.

## Importante

- No subas `instance/pos_v2.db` al repo.
- No hardcodees la clave en `app.py`, `render.yaml` ni `.bat`.
- Si el usuario ya existe, el bootstrap no lo pisa ni cambia su password.
