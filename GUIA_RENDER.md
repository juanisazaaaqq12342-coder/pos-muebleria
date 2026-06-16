# Despliegue en Render

## 1. Crear los servicios en Render

- Sube este proyecto a GitHub.
- En Render, crea un nuevo Blueprint apuntando al repositorio.
- Render leerá `render.yaml` y te propondrá:
  - un `web service`
  - una base `Postgres`

## 2. Migrar la base local SQLite a Postgres

Antes de correr la migración, copia `instance/pos_v2.db`, `instance/pos_v2.db-wal` y `instance/pos_v2.db-shm` como respaldo.

En tu terminal local, dentro de la carpeta del proyecto:

```powershell
$env:DATABASE_URL="postgresql://USUARIO:CLAVE@HOST:PUERTO/NOMBRE_DB"
python migrate_sqlite_to_postgres.py
```

Si quieres conservar datos existentes en Postgres y solo agregar lo que falta:

```powershell
python migrate_sqlite_to_postgres.py --keep-target
```

## 3. Arranque y despliegue automáticos

El archivo `render.yaml` ya quedó configurado con:

- `autoDeployTrigger: commit`
- `startCommand: gunicorn wsgi:app --bind 0.0.0.0:$PORT`
- `plan: free` para el web service
- `plan: free` para Postgres

Eso significa:

- Cada `push` a la rama conectada dispara un deploy.
- Luego arranca la app con Gunicorn.
- La inicialización básica ocurre al arrancar la app mediante `wsgi.py`.

## 4. Imágenes persistentes

En modo gratis no usamos disco persistente. Las imágenes de productos se guardan en:

- `MEDIA_ROOT: /opt/render/project/src/static/img/productos`

Esto sirve para pruebas, pero no garantiza persistencia después de redeploys o reinicios del servicio.

## 5. Limitaciones del modo gratis

- El web service usa la instancia `Free`.
- La base `Render Postgres` usa el plan `Free`.
- El plan `Free` de Postgres en Render tiene límite de 30 días.
- No hay disco persistente para archivos subidos.

## 6. Recomendación

Para cambios futuros de esquema más complejos, conviene luego incorporar migraciones formales con Alembic o Flask-Migrate. El predeploy actual sirve bien para inicialización y creación de tablas faltantes, pero no reemplaza una estrategia completa de migraciones versionadas.
