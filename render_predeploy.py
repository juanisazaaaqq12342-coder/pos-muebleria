from app import app, crear_datos_iniciales, db


def main():
    with app.app_context():
        db.create_all()
        crear_datos_iniciales()
    print("Predeploy completado.")


if __name__ == "__main__":
    main()
