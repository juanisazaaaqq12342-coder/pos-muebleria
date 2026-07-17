# Conectar Supabase con Render

## 1. Crear el proyecto en Supabase
- Entra a Supabase y crea un proyecto nuevo.
- Espera a que la base termine de aprovisionarse.

## 2. Copiar el DATABASE_URL correcto
- En el proyecto, pulsa `Connect`.
- Copia la cadena `Session pooler`.
- Debe verse parecida a esta:

```text
postgres://postgres.TU_PROJECT_REF:TU_PASSWORD@aws-REGION.pooler.supabase.com:5432/postgres
```

## 3. Pegar la variable en Render
- Entra a tu servicio web en Render.
- Ve a `Environment`.
- Busca `DATABASE_URL`.
- Pega la cadena de Supabase.
- Guarda con `Save, rebuild, and deploy`.

## 4. Migrar los datos actuales
Si quieres pasar los datos de tu SQLite local a Supabase, desde la carpeta del proyecto ejecuta:

```powershell
$env:DATABASE_URL="postgres://postgres.TU_PROJECT_REF:TU_PASSWORD@aws-REGION.pooler.supabase.com:5432/postgres"
python migrate_sqlite_to_postgres.py --source "instance/pos_v2.db"
```

Si la URL empieza por `postgres://`, el script la normaliza automaticamente.

## 5. Verificar
- Abre tu app en Render.
- Inicia sesion.
- Revisa clientes, inventario y cobranzas.
- Si todo se ve bien, ya puedes dejar de usar la DB de Render.

## Nota importante
- Este proyecto ya soporta Postgres por `DATABASE_URL`.
- No debes poner la clave de Supabase en el repo.
- El valor se guarda solo en `Environment` de Render.
