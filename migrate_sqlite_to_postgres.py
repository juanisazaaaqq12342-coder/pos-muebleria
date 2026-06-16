import argparse
import os

from sqlalchemy import MetaData, create_engine, inspect, select, text


def normalize_database_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def chunked_rows(conn, table, batch_size=500):
    result = conn.execution_options(stream_results=True).execute(select(table))
    while True:
        rows = result.mappings().fetchmany(batch_size)
        if not rows:
            break
        yield [dict(row) for row in rows]


def reset_postgres_sequences(conn, metadata):
    for table in metadata.sorted_tables:
        pk_cols = list(table.primary_key.columns)
        if len(pk_cols) != 1:
            continue
        pk_col = pk_cols[0]
        seq_name = conn.execute(
            text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
            {"table_name": table.name, "column_name": pk_col.name},
        ).scalar()
        if not seq_name:
            continue
        conn.execute(
            text(
                """
                SELECT setval(
                    :seq_name,
                    COALESCE((SELECT MAX(%s) FROM %s), 1),
                    COALESCE((SELECT MAX(%s) FROM %s), 0) > 0
                )
                """
                % (pk_col.name, table.name, pk_col.name, table.name)
            ),
            {"seq_name": seq_name},
        )


def main():
    parser = argparse.ArgumentParser(
        description="Migra datos desde SQLite local hacia Postgres (Render)."
    )
    parser.add_argument(
        "--source",
        default=os.path.join("instance", "pos_v2.db"),
        help="Ruta al archivo SQLite origen.",
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("DATABASE_URL", ""),
        help="Connection string del Postgres destino. Si se omite, usa DATABASE_URL.",
    )
    parser.add_argument(
        "--keep-target",
        action="store_true",
        help="No limpia las tablas destino antes de importar.",
    )
    args = parser.parse_args()

    source_path = os.path.abspath(args.source)
    if not os.path.exists(source_path):
        raise SystemExit(f"No existe la base SQLite origen: {source_path}")

    target_url = normalize_database_url(args.target)
    if not target_url:
        raise SystemExit("Debes definir DATABASE_URL o pasar --target.")
    if not target_url.startswith("postgresql"):
        raise SystemExit("El destino debe ser Postgres.")

    os.environ["DATABASE_URL"] = target_url

    from app import app, db  # noqa: WPS433

    with app.app_context():
        db.create_all()

    source_engine = create_engine(f"sqlite:///{source_path}")
    target_engine = create_engine(target_url)

    source_meta = MetaData()
    target_meta = MetaData()
    source_meta.reflect(bind=source_engine)
    target_meta.reflect(bind=target_engine)
    target_tables = {table.name for table in target_meta.sorted_tables}

    with target_engine.begin() as target_conn:
        if not args.keep_target:
            for table in reversed(target_meta.sorted_tables):
                target_conn.execute(text(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE'))

        with source_engine.connect() as source_conn:
            for source_table in source_meta.sorted_tables:
                if source_table.name not in target_tables:
                    continue
                target_table = target_meta.tables[source_table.name]
                inserted = 0
                for batch in chunked_rows(source_conn, source_table):
                    target_conn.execute(target_table.insert(), batch)
                    inserted += len(batch)
                print(f"[MIGRADO] {source_table.name}: {inserted} filas")

        reset_postgres_sequences(target_conn, target_meta)

    print("Migracion completada correctamente.")


if __name__ == "__main__":
    main()
