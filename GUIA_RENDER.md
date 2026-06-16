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
- `preDeployCommand: python render_predeploy.py`
- `startCommand: gunicorn wsgi:app --bind 0.0.0.0:$PORT`

Eso significa:

- Cada `push` a la rama conectada dispara un deploy.
- Antes de publicar la nueva versión, Render ejecuta el predeploy.
- Luego arranca la app con Gunicorn.

## 4. Imágenes persistentes

Las imágenes de productos se guardan en el disco persistente configurado con:

- `mountPath: /opt/render/project/src/uploads`
- `MEDIA_ROOT: /opt/render/project/src/uploads/productos`

## 5. Recomendación

Para cambios futuros de esquema más complejos, conviene luego incorporar migraciones formales con Alembic o Flask-Migrate. El predeploy actual sirve bien para inicialización y creación de tablas faltantes, pero no reemplaza una estrategia completa de migraciones versionadas.
