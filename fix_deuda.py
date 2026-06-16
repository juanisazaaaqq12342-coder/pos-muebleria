import os
from app import app, db, Cliente

def remove_negative_debt():
    with app.app_context():
        clientes = Cliente.query.filter(Cliente.deuda < 0).all()
        for c in clientes:
            print(f"Limpiando deuda del cliente {c.nombre} (Deuda anterior: {c.deuda})")
            c.deuda = 0
            
        db.session.commit()
        print(f"Borrados saldos negativos de {len(clientes)} clientes.")

if __name__ == "__main__":
    remove_negative_debt()
