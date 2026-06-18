# POS Muebleria

Sistema POS para muebleria con:

- ventas
- clientes
- creditos y cartera
- inventario por sede
- reportes
- despliegue en Render
- uso opcional de dominio en Cloudflare

## Ejecutar local

```powershell
python app.py
```

O usando el iniciador:

```powershell
iniciar_sistema.bat
```

## Despliegue en Render

Archivos clave:

- `render.yaml`
- `wsgi.py`
- `render_predeploy.py`
- `migrate_sqlite_to_postgres.py`
- `GUIA_RENDER.md`

## Base de datos

- Desarrollo local: SQLite en `instance/pos_v2.db`
- Produccion recomendada: Postgres en Render con `DATABASE_URL`

## Admin bootstrap sincronizable

Si creas un admin nuevo solo en la SQLite local, ese cambio no viaja por Git porque `instance/pos_v2.db` esta ignorada.

Para recrear el mismo admin en otros entornos, define estas variables antes de arrancar la app:

- `BOOTSTRAP_ADMIN_USERNAME`
- `BOOTSTRAP_ADMIN_PASSWORD`

Al iniciar, el sistema crea ese usuario admin solo si no existe y no modifica usuarios previos.

## Dominio

El proyecto puede publicarse en Render y exponerse con dominio propio manejado en Cloudflare.
