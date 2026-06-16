"""
migrate_db.py - Migración segura de base de datos
Agrega columnas nuevas sin borrar datos existentes.
Ejecutar UNA VEZ: python migrate_db.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "pos_v2.db")

def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    return column in cols

def table_exists(cursor, table):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cursor.fetchone() is not None

def migrate():
    print(f"Conectando a: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ── Configuracion: columnas de intereses ──────────────────────────────────
    cfg_cols = [
        ("interes_semanal",          "REAL DEFAULT 3.0"),
        ("interes_quincenal",        "REAL DEFAULT 5.0"),
        ("interes_mensual",          "REAL DEFAULT 8.0"),
        ("mora_porcentaje",          "REAL DEFAULT 2.0"),
        ("dias_gracia",              "INTEGER DEFAULT 0"),
        ("aplicar_interes_credito",  "INTEGER DEFAULT 1"),
    ]
    for col, typedef in cfg_cols:
        if not column_exists(cur, "configuracion", col):
            cur.execute(f"ALTER TABLE configuracion ADD COLUMN {col} {typedef}")
            print(f"  [+] configuracion.{col}")

    # ── Credito: columnas nuevas ──────────────────────────────────────────────
    credito_cols = [
        ("cuota_inicial",      "INTEGER DEFAULT 0"),
        ("saldo_financiar",    "INTEGER DEFAULT 0"),
        ("porcentaje_interes", "REAL DEFAULT 0.0"),
        ("valor_interes",      "INTEGER DEFAULT 0"),
        ("total_financiado",   "INTEGER DEFAULT 0"),
    ]
    for col, typedef in credito_cols:
        if not column_exists(cur, "credito", col):
            cur.execute(f"ALTER TABLE credito ADD COLUMN {col} {typedef}")
            print(f"  [+] credito.{col}")

    # Normalizar estado existente (activo → Activo)
    cur.execute("UPDATE credito SET estado='Activo' WHERE estado='activo'")
    cur.execute("UPDATE credito SET estado='Cancelado' WHERE estado='cancelado'")

    # Rellenar saldo_financiar y total_financiado para créditos antiguos
    cur.execute("""
        UPDATE credito SET saldo_financiar = monto_total, total_financiado = monto_total
        WHERE saldo_financiar = 0 AND monto_total > 0
    """)

    # ── AbonoCredito: columna cuota_id y metodo_pago ──────────────────────────
    abono_cols = [
        ("cuota_id",    "INTEGER REFERENCES cuota_credito(id)"),
        ("metodo_pago", "TEXT"),
    ]
    for col, typedef in abono_cols:
        if not column_exists(cur, "abono_credito", col):
            cur.execute(f"ALTER TABLE abono_credito ADD COLUMN {col} {typedef}")
            print(f"  [+] abono_credito.{col}")

    # ── Tabla CuotaCredito (nueva) ────────────────────────────────────────────
    if not table_exists(cur, "cuota_credito"):
        cur.execute("""
            CREATE TABLE cuota_credito (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                credito_id       INTEGER NOT NULL REFERENCES credito(id),
                numero_cuota     INTEGER NOT NULL,
                fecha_vencimiento DATETIME NOT NULL,
                valor_cuota      INTEGER NOT NULL,
                valor_pagado     INTEGER DEFAULT 0,
                saldo_pendiente  INTEGER NOT NULL,
                estado           TEXT DEFAULT 'Pendiente',
                fecha_pago       DATETIME,
                metodo_pago      TEXT,
                observacion      TEXT,
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("  [+] Tabla cuota_credito creada")

    conn.commit()
    conn.close()
    print("\n✅ Migración completada exitosamente.")

if __name__ == "__main__":
    migrate()
