import os
import locale
import math
import json
import sqlite3
import calendar
import unicodedata
from datetime import datetime, timedelta
from sqlalchemy import func, event, or_, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

from fpdf import FPDF

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_file, abort, g, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

# ==========================
# SEGURIDAD
# ==========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión.", "warning")
            nxt = request.full_path if request.query_string else request.path
            return redirect(url_for("login", next=nxt))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "admin":
            flash("Acceso denegado: Se requieren permisos de Administrador.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

def cobrador_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") not in ["admin", "cobrador"]:
            flash("Acceso denegado.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

def inventario_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") not in ["admin", "bodega", "vendedor"]:
            flash("Acceso denegado: módulo solo para inventario.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# ==========================
# CONFIGURACIÓN
# ==========================

import sys

if getattr(sys, 'frozen', False):
    # Si se ejecuta como .exe (compilado)
    base_dir = os.path.dirname(sys.executable)
else:
    # Si se ejecuta normalmente
    base_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            static_folder=os.path.join(base_dir, 'static'), 
            template_folder=os.path.join(base_dir, 'templates'))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cambia_esta_clave_en_produccion")
BRAND_LOGO_STATIC = 'img/logo_muebleria.jpg'
BRAND_LOGO_VERSION = '20260619'
BRAND_LOGO_PATH = os.path.join(app.static_folder, 'img', 'logo_muebleria.jpg')
app.jinja_env.globals['brand_logo_static'] = BRAND_LOGO_STATIC
app.jinja_env.globals['brand_logo_version'] = BRAND_LOGO_VERSION

# DB CONFIG
instance_path = os.path.join(base_dir, "instance")
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

local_db_path = os.path.join(instance_path, "pos_v2.db")
database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = "postgresql://" + database_url[len("postgres://"):]
if not database_url:
    database_url = "sqlite:///" + local_db_path

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

default_upload_folder = os.path.join(base_dir, 'static', 'img', 'productos')
app.config["UPLOAD_FOLDER"] = os.environ.get("MEDIA_ROOT", default_upload_folder)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# SEGURIDAD EXTRA
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024 # Limite 5MB para uploads
)

# LIMITADOR DE SESIONES (Anti-Brute Force simple)
failed_logins = {} # {ip: {'count': 0, 'last_fail': datetime}}
schema_ensured = False

import secrets

@app.before_request
def load_config():
    global schema_ensured
    if not schema_ensured:
        try:
            db.create_all()
            asegurar_columnas_configuracion()
            asegurar_columnas_cliente()
            asegurar_password_hash_largo()
            schema_ensured = True
        except Exception as schema_err:
            app.logger.warning("No se pudo verificar esquema en load_config: %s", schema_err)

    # Session setup
    session.permanent = True
    
    # Generar token CSRF si no existe
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
        
    try:
        g.config = Configuracion.query.first() or Configuracion()
        usuario_sesion = obtener_usuario_actual() if session.get("user_id") else None
        g.todas_sedes = sedes_visibles_para_usuario(usuario_sesion)
        if usuario_sesion and usuario_sesion.rol != "admin" and usuario_sesion.sede_id:
            session["sede_id"] = usuario_sesion.sede_id
        curr_sede_id = session.get("sede_id")
        sede_actual = obtener_sede_activa(curr_sede_id)
        if not sede_actual and g.todas_sedes:
            sede_actual = g.todas_sedes[0]
            if sede_actual:
                session["sede_id"] = sede_actual.id
        if sede_actual:
            g.sede_nombre = sede_actual.nombre
        elif g.todas_sedes:
            g.sede_nombre = g.todas_sedes[0].nombre
        else:
            g.sede_nombre = "Sede Principal"
    except Exception as e:
        g.config = Configuracion()
        g.todas_sedes = []
        g.sede_nombre = "Error DB"
        
    # Proteccion CSRF Global para POST
    if request.method == "POST":
        csrf_response = csrf_protect()
        if csrf_response:
            return csrf_response

def csrf_protect():
    token = session.get('csrf_token')
    form_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != form_token:
        # Silenciosamente permitir si es una peticion interna que ya validamos? No, seamos estrictos
        app.logger.warning(f"CSRF Denied: Session({token}) vs Form({form_token})")
        session['csrf_token'] = secrets.token_hex(16)
        flash("Tu sesion del formulario vencio. Intenta de nuevo.", "warning")
        return redirect(request.referrer or url_for("login"))

@app.route('/favicon.ico')
def favicon():
    return '', 204

db = SQLAlchemy(app)

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite3" not in dbapi_connection.__class__.__module__:
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# ==========================
# MODELOS DE BASE DE DATOS
# ==========================

class Configuracion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_empresa = db.Column(db.String(100), default="Mi Mueblería")
    nit = db.Column(db.String(50), default="000000000")
    direccion = db.Column(db.String(200), default="Dirección Principal")
    telefono = db.Column(db.String(50), default="0000000000")
    mensaje_ticket = db.Column(db.String(200), default="¡Gracias por su compra!")
    base_caja = db.Column(db.Integer, default=0)
    # Configuración de créditos e intereses
    interes_semanal = db.Column(db.Float, default=3.0)
    interes_quincenal = db.Column(db.Float, default=5.0)
    interes_mensual = db.Column(db.Float, default=8.0)
    mora_porcentaje = db.Column(db.Float, default=2.0)
    dias_gracia = db.Column(db.Integer, default=0)
    aplicar_interes_credito = db.Column(db.Boolean, default=True)
    dias_pago_semanal = db.Column(db.Text, default='[{"value":"1","label":"Lunes"},{"value":"2","label":"Martes"},{"value":"3","label":"Miercoles"},{"value":"4","label":"Jueves"},{"value":"5","label":"Viernes"},{"value":"6","label":"Sabado"},{"value":"0","label":"Domingo"}]')
    dias_pago_quincenal = db.Column(db.Text, default=lambda: json.dumps([{"value": str(i), "label": f"Dia {i}"} for i in range(1, 32)], ensure_ascii=False))
    dias_pago_mensual = db.Column(db.Text, default=lambda: json.dumps([{"value": str(i), "label": f"Dia {i}"} for i in range(1, 31)], ensure_ascii=False))

class Sede(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    direccion = db.Column(db.String(200))
    telefono = db.Column(db.String(50))
    activa = db.Column(db.Boolean, default=True)
    usuarios = db.relationship("Usuario", backref="sede", lazy=True)

class Categoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False)  # admin, vendedor, cobrador, bodega
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'), nullable=True)

class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=True)
    documento = db.Column(db.String(20), unique=True, nullable=True)
    telefono = db.Column(db.String(20))
    direccion = db.Column(db.String(200))
    email = db.Column(db.String(100))
    notas = db.Column(db.Text)
    fecha_registro = db.Column(db.DateTime, default=datetime.now)
    deuda = db.Column(db.Integer, default=0)
    referencias = db.relationship("ReferenciaCliente", backref="cliente", lazy=True, cascade="all, delete-orphan")

class ReferenciaCliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    credito_id = db.Column(db.Integer, db.ForeignKey('credito.id'), nullable=True)
    orden = db.Column(db.Integer, nullable=False, default=1)  # 1 o 2
    nombre = db.Column(db.String(120), nullable=False)
    celular = db.Column(db.String(30), nullable=False)
    parentesco = db.Column(db.String(80), nullable=True)
    direccion = db.Column(db.String(220), nullable=True)
    fecha_registro = db.Column(db.DateTime, default=datetime.now)

class MovimientoCredito(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.now)
    tipo = db.Column(db.String(20), nullable=False)  # 'cargo' (fiado), 'abono' (pago)
    monto = db.Column(db.Integer, nullable=False)
    nota = db.Column(db.String(200))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    cliente = db.relationship("Cliente", backref="movimientos")

class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    precio = db.Column(db.Integer, nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=True)
    categoria_rel = db.relationship('Categoria', backref='productos')
    descripcion = db.Column(db.String(300))
    imagen_url = db.Column(db.String(255), nullable=True)
    activo = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)

class InventarioSede(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'), nullable=False)
    cantidad = db.Column(db.Integer, default=0)
    cantidad_danado = db.Column(db.Integer, default=0)
    producto = db.relationship("Producto", backref=db.backref("inventarios", lazy=True))
    sede_rel = db.relationship("Sede")

class Venta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.now)
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'), nullable=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=True)
    vendedor_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    estado = db.Column(db.String(50), default='abierta')  # abierta, pagada, crédito, cotización
    estado_entrega = db.Column(db.String(50), default='Pendiente') # Pendiente, En Ruta, Entregado
    direccion_envio = db.Column(db.String(255), nullable=True)
    cerrado = db.Column(db.Boolean, default=False)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    metodo_pago = db.Column(db.String(50))  # Efectivo, Transferencia, Tarjeta, Credito, Mixto
    pago_efectivo = db.Column(db.Integer, default=0)
    pago_tarjeta = db.Column(db.Integer, default=0)
    pago_transferencia = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)
    monto_recibido = db.Column(db.Integer, default=0)
    cambio = db.Column(db.Integer, default=0)
    notas = db.Column(db.String(300))
    items = db.relationship("DetalleVenta", backref="venta", lazy=True, cascade="all, delete-orphan")
    cliente = db.relationship("Cliente", backref="ventas")
    sede = db.relationship("Sede", foreign_keys=[sede_id])
    vendedor = db.relationship("Usuario", foreign_keys=[vendedor_id])

class DetalleVenta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    venta_id = db.Column(db.Integer, db.ForeignKey('venta.id'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad = db.Column(db.Integer, default=1)
    precio_unitario = db.Column(db.Integer, nullable=False)
    notas = db.Column(db.String(200))
    cantidad_devuelta = db.Column(db.Integer, default=0)
    producto = db.relationship("Producto")

class Gasto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(200), nullable=False)
    monto = db.Column(db.Integer, nullable=False)
    tipo_gasto = db.Column(db.String(50), default='operativo')
    fecha = db.Column(db.DateTime, default=datetime.now)
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    usuario = db.relationship("Usuario")

class Auditoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.now)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    accion = db.Column(db.String(100)) # Login, Delete, Edit, Stock
    detalles = db.Column(db.Text)
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'))
    usuario = db.relationship("Usuario")

class MovimientoInventario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.now)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'))
    sede_id = db.Column(db.Integer, db.ForeignKey('sede.id'))
    tipo = db.Column(db.String(20)) # ENTRADA, SALIDA, DEVOLUCION, AJUSTE
    cantidad = db.Column(db.Integer)
    stock_anterior = db.Column(db.Integer)
    stock_nuevo = db.Column(db.Integer)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    referencia = db.Column(db.String(100)) # Ej: Venta #123
    
    producto = db.relationship("Producto")
    sede = db.relationship("Sede")

class Credito(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(30), unique=True, nullable=False)
    fecha_inicio = db.Column(db.DateTime, default=datetime.now)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    venta_id = db.Column(db.Integer, db.ForeignKey('venta.id'), nullable=False)
    periodicidad = db.Column(db.String(20), default="Mensual")  # Semanal, Quincenal, Mensual
    numero_cuotas = db.Column(db.Integer, default=1)
    monto_total = db.Column(db.Integer, default=0)       # Total original de la venta
    cuota_inicial = db.Column(db.Integer, default=0)     # Pago inicial (enganche)
    saldo_financiar = db.Column(db.Integer, default=0)   # monto_total - cuota_inicial
    porcentaje_interes = db.Column(db.Float, default=0.0)
    valor_interes = db.Column(db.Integer, default=0)
    total_financiado = db.Column(db.Integer, default=0)  # saldo_financiar + valor_interes
    valor_cuota = db.Column(db.Integer, default=0)
    saldo_actual = db.Column(db.Integer, default=0)      # Inicia con total_financiado
    estado = db.Column(db.String(20), default="Activo")  # Activo, Pagado, En mora, Cancelado
    observaciones = db.Column(db.String(300))

    cliente = db.relationship("Cliente", backref="creditos")
    venta = db.relationship("Venta", backref="creditos")
    cuotas = db.relationship("CuotaCredito", backref="credito", lazy=True, cascade="all, delete-orphan")
    referencias = db.relationship("ReferenciaCliente", backref="credito", lazy=True)

class CuotaCredito(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credito_id = db.Column(db.Integer, db.ForeignKey('credito.id'), nullable=False)
    numero_cuota = db.Column(db.Integer, nullable=False)
    fecha_vencimiento = db.Column(db.DateTime, nullable=False)
    valor_cuota = db.Column(db.Integer, nullable=False)
    valor_pagado = db.Column(db.Integer, default=0)
    saldo_pendiente = db.Column(db.Integer, nullable=False)
    estado = db.Column(db.String(20), default="Pendiente")  # Pendiente, Vence hoy, Vencida, Abonada, Pagada, Cancelada
    fecha_pago = db.Column(db.DateTime, nullable=True)
    metodo_pago = db.Column(db.String(50), nullable=True)
    observacion = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class AbonoCredito(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credito_id = db.Column(db.Integer, db.ForeignKey('credito.id'), nullable=False)
    cuota_id = db.Column(db.Integer, db.ForeignKey('cuota_credito.id'), nullable=True)
    fecha = db.Column(db.DateTime, default=datetime.now)
    numero_cuota = db.Column(db.Integer, nullable=True)
    monto = db.Column(db.Integer, nullable=False)
    saldo_posterior = db.Column(db.Integer, default=0)
    metodo_pago = db.Column(db.String(50), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    nota = db.Column(db.String(200))

    credito = db.relationship("Credito", backref="abonos")
    usuario = db.relationship("Usuario")

# ==========================
# HELPERS & LOGGING
# ==========================
def registrar_auditoria(accion, detalles):
    try:
        uid = session.get("user_id")
        sid = session.get("sede_id")
        log = Auditoria(usuario_id=uid, accion=accion, detalles=detalles, sede_id=sid)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error al registrar auditoria: {e}")
        db.session.rollback()

# ==========================
# HELPERS
# ==========================
@app.context_processor
def inject_globals():
    conf = None
    try:
        conf = Configuracion.query.first() or Configuracion()
    except:
        conf = Configuracion()
    if not conf:
        conf = Configuracion()
    return dict(configuracion=conf, producto_image_url=producto_image_url)

def producto_image_url(filename):
    if not filename:
        return ""
    return url_for("producto_media", filename=filename)

@app.route("/media/productos/<path:filename>")
def producto_media(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

def parse_non_negative_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None

def normalizar_busqueda(texto):
    txt = (texto or "").strip().lower()
    if not txt:
        return ""
    return "".join(
        c for c in unicodedata.normalize("NFD", txt)
        if unicodedata.category(c) != "Mn"
    )

def normalizar_telefono(raw_phone):
    if not raw_phone:
        return ""
    return "".join(ch for ch in str(raw_phone) if ch.isdigit())

def normalizar_documento(raw_doc):
    if not raw_doc:
        return ""
    return "".join(ch for ch in str(raw_doc).strip() if ch.isalnum() or ch in ['-', '.']).upper()

def opciones_dia_pago_default():
    return {
        "Semanal": [
            {"value": "1", "label": "Lunes"},
            {"value": "2", "label": "Martes"},
            {"value": "3", "label": "Miercoles"},
            {"value": "4", "label": "Jueves"},
            {"value": "5", "label": "Viernes"},
            {"value": "6", "label": "Sabado"},
            {"value": "0", "label": "Domingo"},
        ],
        "Quincenal": [
            {"value": str(i), "label": f"Dia {i}"} for i in range(1, 32)
        ],
        "Mensual": [
            {"value": str(i), "label": f"Dia {i}"} for i in range(1, 31)
        ],
    }

def serializar_opciones_dia_pago(opciones):
    try:
        return json.dumps(opciones, ensure_ascii=False)
    except Exception:
        return "[]"

def deserializar_opciones_dia_pago(raw, fallback):
    try:
        data = json.loads(raw) if raw else []
        if not isinstance(data, list):
            return fallback
        limpias = []
        for it in data:
            if not isinstance(it, dict):
                continue
            v = str(it.get("value", "")).strip()
            l = str(it.get("label", v)).strip()
            if not v:
                continue
            limpias.append({"value": v, "label": l or v})
        return limpias or fallback
    except Exception:
        return fallback

def opciones_dia_pago_desde_config(conf):
    defaults = opciones_dia_pago_default()
    quincenal = deserializar_opciones_dia_pago(getattr(conf, "dias_pago_quincenal", None), defaults["Quincenal"])
    mensual = deserializar_opciones_dia_pago(getattr(conf, "dias_pago_mensual", None), defaults["Mensual"])

    quincenal_values = {str(it.get("value", "")).strip() for it in quincenal}
    mensual_values = {str(it.get("value", "")).strip() for it in mensual}
    if len(quincenal_values) < 31:
        quincenal = defaults["Quincenal"]
    if len(mensual_values) < 30:
        mensual = defaults["Mensual"]

    return {
        "Semanal": deserializar_opciones_dia_pago(getattr(conf, "dias_pago_semanal", None), defaults["Semanal"]),
        "Quincenal": quincenal,
        "Mensual": mensual,
    }

def parsear_opciones_desde_texto(periodicidad, texto):
    lineas = [ln.strip() for ln in (texto or "").splitlines() if ln.strip()]
    opts = []
    for ln in lineas:
        if "|" in ln:
            val, lbl = ln.split("|", 1)
        else:
            val, lbl = ln, ln
        val = str(val).strip()
        lbl = str(lbl).strip() or val
        if not val:
            continue
        try:
            vi = int(val)
        except Exception:
            continue
        if periodicidad == "Semanal" and 0 <= vi <= 6:
            opts.append({"value": str(vi), "label": lbl})
        elif periodicidad == "Quincenal" and 1 <= vi <= 31:
            opts.append({"value": str(vi), "label": lbl})
        elif periodicidad == "Mensual" and 1 <= vi <= 30:
            opts.append({"value": str(vi), "label": lbl})
    return opts

def opciones_dia_pago_a_texto(opciones):
    return "\n".join([f'{o.get("value","")}|{o.get("label","")}' for o in (opciones or [])])

def asegurar_columnas_configuracion():
    if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        return
    db_path = local_db_path
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='configuracion'")
        if not cur.fetchone():
            return
        cur.execute("PRAGMA table_info(configuracion)")
        cols = {r[1] for r in cur.fetchall()}
        alters = []
        if "dias_pago_semanal" not in cols:
            alters.append("ALTER TABLE configuracion ADD COLUMN dias_pago_semanal TEXT")
        if "dias_pago_quincenal" not in cols:
            alters.append("ALTER TABLE configuracion ADD COLUMN dias_pago_quincenal TEXT")
        if "dias_pago_mensual" not in cols:
            alters.append("ALTER TABLE configuracion ADD COLUMN dias_pago_mensual TEXT")
        for q in alters:
            cur.execute(q)
        conn.commit()
    finally:
        conn.close()

def asegurar_columnas_cliente():
    if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        return
    db_path = local_db_path
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cliente'")
        if not cur.fetchone():
            return
        cur.execute("PRAGMA table_info(cliente)")
        cols = {r[1] for r in cur.fetchall()}
        alters = []
        if "apellido" not in cols:
            alters.append("ALTER TABLE cliente ADD COLUMN apellido TEXT")
        for q in alters:
            cur.execute(q)
        conn.commit()
    finally:
        conn.close()

def asegurar_password_hash_largo():
    try:
        inspector = inspect(db.engine)
        tablas = set(inspector.get_table_names())
        if "usuario" not in tablas:
            return
        columnas = {col["name"]: col for col in inspector.get_columns("usuario")}
        password_col = columnas.get("password_hash")
        if not password_col:
            return
        largo_actual = getattr(password_col.get("type"), "length", None)
        if largo_actual is not None and largo_actual >= 255:
            return
        if db.engine.dialect.name == "postgresql":
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE usuario ALTER COLUMN password_hash TYPE VARCHAR(255)"))
    except Exception as schema_err:
        app.logger.warning("No se pudo ajustar columna password_hash: %s", schema_err)

def nombre_completo_cliente(cliente):
    if not cliente:
        return "Consumidor Final"
    nom = (cliente.nombre or "").strip()
    ape = (getattr(cliente, "apellido", "") or "").strip()
    full = " ".join([p for p in [nom, ape] if p])
    return full or nom or "Consumidor Final"

def extraer_referencias_desde_observaciones(obs):
    refs = []
    texto = (obs or "").splitlines()
    for ln in texto:
        ln = (ln or "").strip()
        if not ln.lower().startswith("referencia "):
            continue
        # Formato esperado:
        # Referencia 1: Nombre=... | Parentesco=... | Celular=... | Direccion=...
        try:
            pref, detalle = ln.split(":", 1)
        except ValueError:
            continue
        orden = 1
        if "2" in pref:
            orden = 2
        partes = [p.strip() for p in detalle.split("|") if p.strip()]
        data = {"orden": orden, "nombre": "", "celular": "", "parentesco": "", "direccion": ""}
        for p in partes:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            kk = k.strip().lower()
            vv = v.strip()
            if kk == "nombre":
                data["nombre"] = vv
            elif kk == "celular":
                data["celular"] = vv
            elif kk == "parentesco":
                data["parentesco"] = vv
            elif kk in {"direccion", "dirección"}:
                data["direccion"] = vv
        if data["nombre"] or data["celular"]:
            refs.append(data)
    # Dejar solo max 2 referencias ordenadas.
    refs = sorted(refs, key=lambda x: x.get("orden", 9))
    return refs[:2]

def recalcular_total_venta(venta):
    if not venta:
        return 0
    venta.total = sum((i.precio_unitario or 0) * (i.cantidad or 0) for i in venta.items)
    return venta.total

def venta_editable_por_usuario(venta):
    if not venta:
        return False
    if venta.cerrado:
        return False
    if session.get("rol") == "admin":
        return True
    return (venta.vendedor_id == session.get("user_id")) and (venta.cerrado is False)

def obtener_stock_producto_sede(producto_id, sede_id):
    inv = InventarioSede.query.filter_by(producto_id=producto_id, sede_id=sede_id).first()
    return (inv.cantidad if inv else 0), inv

def validar_stock_venta(venta):
    if not venta:
        return False, "Venta no valida."
    cantidades = {}
    for item in venta.items:
        cantidades[item.producto_id] = cantidades.get(item.producto_id, 0) + (item.cantidad or 0)
    for producto_id, cantidad_requerida in cantidades.items():
        stock_disponible, _ = obtener_stock_producto_sede(producto_id, venta.sede_id)
        if cantidad_requerida > stock_disponible:
            prod = db.session.get(Producto, producto_id)
            nombre_prod = prod.nombre if prod else f"Producto #{producto_id}"
            return False, f"Stock insuficiente para {nombre_prod}: disponible {stock_disponible}, solicitado {cantidad_requerida}."
    return True, ""

def desglose_pago_venta(venta):
    efectivo = venta.pago_efectivo or 0
    tarjeta = venta.pago_tarjeta or 0
    transferencia = venta.pago_transferencia or 0
    if efectivo == 0 and tarjeta == 0 and transferencia == 0:
        if venta.metodo_pago == "Efectivo":
            efectivo = venta.total or 0
        elif venta.metodo_pago == "Tarjeta":
            tarjeta = venta.total or 0
        elif venta.metodo_pago == "Transferencia":
            transferencia = venta.total or 0
    return efectivo, tarjeta, transferencia

def sincronizar_cartera_cliente(cliente_id):
    if not cliente_id:
        return 0
    cliente = db.session.get(Cliente, cliente_id)
    if not cliente:
        return 0
    total_cargos = db.session.query(func.sum(MovimientoCredito.monto)).filter(
        MovimientoCredito.cliente_id == cliente_id,
        MovimientoCredito.tipo == "cargo"
    ).scalar() or 0
    total_abonos = db.session.query(func.sum(MovimientoCredito.monto)).filter(
        MovimientoCredito.cliente_id == cliente_id,
        MovimientoCredito.tipo == "abono"
    ).scalar() or 0
    deuda_por_movimientos = max(int(total_cargos) - int(total_abonos), 0)
    deuda_por_creditos = db.session.query(func.sum(Credito.saldo_actual)).filter(
        Credito.cliente_id == cliente_id,
        Credito.estado == "Activo"
    ).scalar() or 0
    cliente.deuda = max(deuda_por_movimientos, int(deuda_por_creditos))
    return cliente.deuda

def sincronizar_cartera_global():
    """
    Recalcula deuda para todos los clientes que tengan al menos
    un movimiento de cartera o un credito activo.
    """
    ids_mov = db.session.query(MovimientoCredito.cliente_id).distinct().all()
    ids_cred = db.session.query(Credito.cliente_id).filter(Credito.estado == "activo").distinct().all()
    ids = {cid for (cid,) in ids_mov if cid} | {cid for (cid,) in ids_cred if cid}
    for cid in ids:
        sincronizar_cartera_cliente(cid)

def generar_codigo_credito():
    ultimo = Credito.query.order_by(Credito.id.desc()).first()
    next_num = (ultimo.id + 1) if ultimo else 1
    return f"CR-{datetime.now().strftime('%Y%m')}-{next_num:04d}"

def obtener_credito_activo_cliente(cliente_id):
    return Credito.query.filter_by(cliente_id=cliente_id, estado="Activo").order_by(Credito.fecha_inicio.asc()).first()

def obtener_usuario_actual():
    user_id = session.get("user_id")
    return db.session.get(Usuario, user_id) if user_id else None

def obtener_sede_activa(sede_id):
    return Sede.query.filter_by(id=sede_id, activa=True).first() if sede_id else None

def sedes_visibles_para_usuario(usuario=None):
    usuario = usuario or obtener_usuario_actual()
    if usuario and usuario.rol != "admin":
        sede_usuario = obtener_sede_activa(usuario.sede_id)
        return [sede_usuario] if sede_usuario else []
    return Sede.query.filter_by(activa=True).order_by(Sede.nombre.asc()).all()

def usuario_puede_operar_sede(sede_id, usuario=None):
    usuario = usuario or obtener_usuario_actual()
    if not usuario or usuario.rol == "admin":
        return True
    return bool(usuario.sede_id and int(usuario.sede_id) == int(sede_id))

def generar_plan_pagos(credito, fecha_inicio, dia_pago=None, cuota_desde=1, saldo_objetivo=None):
    """Genera las cuotas pendientes de un credito, incluso si entra ya iniciado."""
    periodicidad = credito.periodicidad
    n_cuotas = max(1, int(credito.numero_cuotas or 1))
    valor = int(credito.valor_cuota or 0)
    fecha = fecha_inicio

    try:
        cuota_desde = int(cuota_desde or 1)
    except (TypeError, ValueError):
        cuota_desde = 1
    cuota_desde = max(1, min(cuota_desde, n_cuotas))
    cuotas_a_generar = (n_cuotas - cuota_desde) + 1

    def add_months(base_date, months_to_add):
        mes = base_date.month + months_to_add
        anio = base_date.year + (mes - 1) // 12
        mes = ((mes - 1) % 12) + 1
        return base_date.replace(year=anio, month=mes)

    def con_dia_seguro(base_date, day_value):
        ultimo = calendar.monthrange(base_date.year, base_date.month)[1]
        dia = max(1, min(int(day_value), ultimo))
        return base_date.replace(day=dia)

    def normalizar_dias_quincenales(raw_value):
        dias = []
        origen = raw_value if isinstance(raw_value, (list, tuple, set)) else [raw_value]
        for item in origen:
            if isinstance(item, str) and ',' in item:
                partes = item.split(',')
            else:
                partes = [item]
            for parte in partes:
                try:
                    vi = int(str(parte).strip())
                except (TypeError, ValueError):
                    continue
                if 1 <= vi <= 31 and vi not in dias:
                    dias.append(vi)
        dias = sorted(dias)
        if not dias:
            dias = [1, 15]
        if len(dias) == 1:
            sugerido = 15 if dias[0] != 15 else 30
            if sugerido not in dias:
                dias.append(sugerido)
        return sorted(dias[:2])

    try:
        dia_pago = int(dia_pago) if dia_pago is not None and not isinstance(dia_pago, (list, tuple, set)) and str(dia_pago).strip() != "" else dia_pago
    except (TypeError, ValueError):
        dia_pago = None

    valor_ultima_cuota = None
    if saldo_objetivo is not None:
        try:
            saldo_objetivo = int(saldo_objetivo)
        except (TypeError, ValueError):
            raise ValueError("El saldo objetivo del plan de pagos no es valido.")
        saldo_objetivo = max(1, saldo_objetivo)
        if cuotas_a_generar == 1:
            valor_ultima_cuota = saldo_objetivo
        else:
            valor_ultima_cuota = saldo_objetivo - (valor * (cuotas_a_generar - 1))
            if valor_ultima_cuota <= 0 or valor_ultima_cuota > valor:
                raise ValueError("La combinacion de saldo pendiente, cuotas y valor por cuota no permite generar el plan de pagos.")

    for offset, i in enumerate(range(cuota_desde, n_cuotas + 1), start=1):
        if periodicidad == "Semanal":
            if dia_pago is None or dia_pago < 0 or dia_pago > 6:
                dia_pago = 1
            weekday_target = (dia_pago - 1) % 7
            delta = (weekday_target - fecha.weekday()) % 7
            if delta == 0:
                delta = 7
            fecha = fecha + timedelta(days=delta)
        elif periodicidad == "Quincenal":
            dias_quincenales = normalizar_dias_quincenales(dia_pago)
            candidatos = []
            for month_offset in range(0, 3):
                base_month = add_months(fecha.replace(day=1), month_offset)
                for dia in dias_quincenales:
                    candidato = con_dia_seguro(base_month, dia)
                    if candidato > fecha:
                        candidatos.append(candidato)
            fecha = min(candidatos) if candidatos else con_dia_seguro(add_months(fecha.replace(day=1), 1), dias_quincenales[0])
        else:
            if dia_pago is None or dia_pago < 1 or dia_pago > 30:
                dia_pago = 1
            candidato = con_dia_seguro(fecha, dia_pago)
            if candidato <= fecha:
                candidato = con_dia_seguro(add_months(candidato, 1), dia_pago)
            fecha = candidato

        valor_cuota_plan = valor
        if saldo_objetivo is not None and offset == cuotas_a_generar:
            valor_cuota_plan = valor_ultima_cuota

        cuota = CuotaCredito(
            credito_id=credito.id,
            numero_cuota=i,
            fecha_vencimiento=fecha,
            valor_cuota=valor_cuota_plan,
            saldo_pendiente=valor_cuota_plan,
            estado="Pendiente"
        )
        db.session.add(cuota)

def actualizar_estados_cuotas():
    """Actualiza automáticamente los estados de cuotas según fecha actual."""
    hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    manana = hoy + timedelta(days=1)
    # Vencidas
    CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento < hoy,
        CuotaCredito.estado.in_(["Pendiente", "Vence hoy"])
    ).update({"estado": "Vencida"}, synchronize_session=False)
    # Vence hoy
    CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= hoy,
        CuotaCredito.fecha_vencimiento < manana,
        CuotaCredito.estado.in_(["Pendiente"])
    ).update({"estado": "Vence hoy"}, synchronize_session=False)

def construir_filas_ficha_credito(credito, max_filas=30):
    filas = []
    abonos = sorted(credito.abonos, key=lambda x: x.fecha)
    for i in range(max_filas):
        if i < len(abonos):
            ab = abonos[i]
            filas.append({
                "n": i + 1,
                "fecha": ab.fecha.strftime('%d/%m/%Y'),
                "abono": ab.monto,
                "resta": ab.saldo_posterior
            })
        else:
            filas.append({"n": i + 1, "fecha": "", "abono": "", "resta": ""})
    return filas

def agrupar_items_venta(venta):
    """Agrupa los ítems de una venta por producto y nota."""
    if not venta or not venta.items:
        return []
    agrupados = {}
    for i in venta.items:
        if not i.producto:
            continue
        key = (i.producto_id, i.notas)
        if key in agrupados:
            agrupados[key]['cantidad'] += i.cantidad
            agrupados[key]['ids'].append(i.id)
        else:
            agrupados[key] = {
                'id_producto': i.producto_id,
                'cantidad': i.cantidad,
                'nombre': i.producto.nombre,
                'precio': i.precio_unitario,
                'notas': i.notas,
                'ids': [i.id],
            }
    return list(agrupados.values())

def asegurar_admin_bootstrap_desde_entorno():
    """
    Crea o sincroniza un admin adicional desde variables de entorno.
    No modifica usuarios distintos al bootstrap indicado.
    """
    username = (os.environ.get("BOOTSTRAP_ADMIN_USERNAME") or "").strip()
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD") or ""
    if not username or len(password) < 4:
        return None

    sede_admin = Sede.query.filter_by(activa=True).order_by(Sede.id.asc()).first()
    if not sede_admin:
        sede_admin = Sede(
            nombre="Sede Principal",
            direccion="Direccion Principal",
            telefono="0000000000"
        )
        db.session.add(sede_admin)
        db.session.flush()

    existente = Usuario.query.filter_by(username=username).first()
    if existente:
        cambios = False
        if not check_password_hash(existente.password_hash, password):
            existente.password_hash = generate_password_hash(password)
            cambios = True
        if existente.rol != "admin":
            existente.rol = "admin"
            cambios = True
        if not existente.sede_id:
            existente.sede_id = sede_admin.id
            cambios = True
        return "updated" if cambios else None

    db.session.add(Usuario(
        username=username,
        password_hash=generate_password_hash(password),
        rol="admin",
        sede_id=sede_admin.id
    ))
    return "created"

def crear_datos_iniciales():
    """Crea las tablas y los datos iniciales del sistema."""
    with app.app_context():
        db.create_all()
        asegurar_columnas_configuracion()
        asegurar_columnas_cliente()
        asegurar_password_hash_largo()
        cambios_pendientes = False
        if not Usuario.query.filter_by(username="admin").first():
            # Sedes
            # Sedes
            sede1 = Sede(nombre="Sede Principal", direccion="Dirección Principal", telefono="0000000000")
            db.session.add(sede1)
            db.session.flush()
            # Usuarios
            db.session.add(Usuario(username="admin", password_hash=generate_password_hash("admin123"), rol="admin", sede_id=sede1.id))
            
            # Config inicial
            db.session.add(Configuracion(nombre_empresa="Mi Empresa POS", nit="000000000"))
            
            # Cliente de muestra
            cliente_demo = Cliente(nombre="Consumidor Final", telefono="0000000000", direccion="N/A")
            db.session.add(cliente_demo)
            db.session.flush()
            sincronizar_cartera_cliente(cliente_demo.id)
            cambios_pendientes = True
            print(">>> SISTEMA MUEBLERíA LISTO")

        estado_bootstrap_admin = asegurar_admin_bootstrap_desde_entorno()
        if estado_bootstrap_admin:
            cambios_pendientes = True
            print(f">>> ADMIN BOOTSTRAP {estado_bootstrap_admin.upper()} DESDE ENTORNO")

        if cambios_pendientes:
            db.session.commit()

# ==========================
# RUTAS SISTEMA
# ==========================
@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    now = datetime.now()
    
    # Verificar bloqueo
    if ip in failed_logins:
        if failed_logins[ip]['count'] >= 5:
            delta = now - failed_logins[ip]['last_fail']
            if delta < timedelta(minutes=10):
                flash(f"Demasiados intentos. Bloqueo temporal por {10 - int(delta.total_seconds()/60)} minutos.", "danger")
                return render_template("login.html")
            else:
                # Reset tras expirar
                failed_logins[ip]['count'] = 0
                
    if request.method == "POST":
        csrf_protect() # Manual CSRF Check
        u = Usuario.query.filter_by(username=request.form.get("username")).first()
        if u and check_password_hash(u.password_hash, request.form.get("password")):
            # Reset exitoso
            if ip in failed_logins:
                failed_logins[ip]['count'] = 0
            
            session.permanent = True
            session["user_id"] = u.id
            session["username"] = u.username
            session["rol"] = u.rol
            session["sede_id"] = u.sede_id
            next_url = (request.args.get("next") or "").strip()
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            if u.rol == "cobrador":
                return redirect(url_for("cobranzas"))
            if u.rol == "bodega":
                return redirect(url_for("admin"))
            return redirect(url_for("index"))
        
        # Registrar fallo
        if ip not in failed_logins:
            failed_logins[ip] = {'count': 1, 'last_fail': now}
        else:
            failed_logins[ip]['count'] += 1
            failed_logins[ip]['last_fail'] = now
            
        flash(f"Credenciales Incorrectas (Intento {failed_logins[ip]['count']}/5)", "danger")
        
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@app.route("/index")
@login_required
def index():
    if session.get("rol") == "cobrador":
        return redirect(url_for("cobranzas"))
    if session.get("rol") == "bodega":
        return redirect(url_for("admin"))
    
    # Datos para el Dashboard
    hoy = datetime.now().replace(hour=0, minute=0, second=0)
    ventas_hoy = Venta.query.filter(
        Venta.cerrado == True,
        Venta.fecha_cierre >= hoy,
        Venta.estado != 'Cotizacion'
    ).all()
    total_hoy = sum(v.total for v in ventas_hoy)
    
    stock_critico = InventarioSede.query.filter(InventarioSede.cantidad <= 2).count()
    cartera_pend = Cliente.query.filter(Cliente.deuda > 0).count()
    
    # Ultimas ventas
    recientes = Venta.query.filter(
        Venta.cerrado == True,
        Venta.estado != 'Cotizacion'
    ).order_by(Venta.fecha_cierre.desc()).limit(5).all()
    
    return render_template("dashboard.html", 
                           total_hoy=total_hoy, 
                           n_ventas=len(ventas_hoy),
                           stock_critico=stock_critico,
                           cartera_pend=cartera_pend,
                           recientes=recientes)

@app.route("/buscar")
@login_required
def buscar_rapido():
    q_raw = (request.args.get("q") or "").strip()
    if not q_raw:
        return redirect(url_for("index"))

    ql = q_raw.lower()
    rol = session.get("rol")
    q_num = parse_non_negative_int(q_raw)
    query_target = None
    term = q_raw

    # Prefijos opcionales para forzar destino:
    # cliente: maria | producto: colchon matrimonial | venta: 123 | cartera: juan
    prefixes = {
        "cliente": "clientes",
        "clientes": "clientes",
        "producto": "productos",
        "productos": "productos",
        "venta": "ventas",
        "ventas": "ventas",
        "cartera": "cobranzas",
        "cobranzas": "cobranzas",
        "credito": "cobranzas",
        "crédito": "cobranzas",
    }
    for k, target in prefixes.items():
        if ql.startswith(k + ":") or ql.startswith(k + " "):
            query_target = target
            term = q_raw[len(k):].lstrip(": ").strip() or q_raw
            break

    term_like = f"%{term}%"

    # Atajos solo cuando el texto completo coincide exactamente con módulo
    if query_target is None:
        exact_nav = {
            "punto de venta": "pos",
            "pos": "pos",
            "inventario": "productos",
            "productos": "productos",
            "clientes": "clientes",
            "ventas": "ventas",
            "cartera": "cobranzas",
            "cobranzas": "cobranzas",
            "reportes": "reportes",
            "caja": "caja",
            "usuarios": "usuarios",
            "sedes": "sedes",
        }
        query_target = exact_nav.get(ql)

    if query_target == "pos":
        if rol == "bodega":
            return redirect(url_for("admin"))
        return redirect(url_for("punto_venta"))
    if query_target == "productos":
        if rol == "bodega":
            return redirect(url_for("admin", q=term))
        # Si es búsqueda real de producto, mejor ir al POS filtrado.
        if term and term.lower() not in ["producto", "productos", "inventario"]:
            return redirect(url_for("punto_venta", categoria="Todas", q=term))
        if rol == "admin":
            return redirect(url_for("admin"))
        return redirect(url_for("punto_venta"))
    if query_target == "clientes" and rol == "admin":
        return redirect(url_for("clientes", q=term))
    if query_target == "ventas" and rol == "admin":
        return redirect(url_for("historial_ventas", q=term))
    if query_target == "cobranzas" and rol in ["admin", "cobrador"]:
        return redirect(url_for("cobranzas", q=term, filtro="todos"))
    if query_target == "reportes" and rol == "admin":
        return redirect(url_for("reportes"))
    if query_target == "caja" and rol == "admin":
        return redirect(url_for("caja"))
    if query_target == "usuarios" and rol == "admin":
        return redirect(url_for("usuarios"))
    if query_target == "sedes" and rol == "admin":
        return redirect(url_for("sedes"))

    # Búsqueda por contenido real (texto libre)
    # 1) Cliente por nombre/teléfono/documento/dirección
    cli_match = (
        Cliente.query
        .filter(
            or_(
                Cliente.nombre.ilike(term_like),
                Cliente.telefono.ilike(term_like),
                Cliente.documento.ilike(term_like),
                Cliente.direccion.ilike(term_like)
            )
        )
        .first()
    )
    if cli_match and rol == "admin":
        return redirect(url_for("clientes", q=term))
    if cli_match and rol in ["admin", "cobrador"]:
        return redirect(url_for("cobranzas", q=term, filtro="todos"))

    # 2) Producto (ej: "colchon matrimonial")
    prod_match = (
        Producto.query
        .outerjoin(Categoria, Producto.categoria_id == Categoria.id)
        .filter(
            Producto.activo == True,
            Producto.is_deleted == False,
            or_(
                Producto.nombre.ilike(term_like),
                Producto.descripcion.ilike(term_like),
                Categoria.nombre.ilike(term_like)
            )
        )
        .first()
    )
    if prod_match and rol in ["admin", "vendedor"]:
        return redirect(url_for("punto_venta", categoria="Todas", q=term))
    if prod_match and rol == "bodega":
        return redirect(url_for("admin", q=term))

    # 3) Venta por ID o texto (solo admin)
    if rol == "admin":
        venta_q = Venta.query.filter(Venta.cerrado == True)
        if q_num is not None:
            v_match = venta_q.filter(Venta.id == q_num).first()
            if v_match:
                return redirect(url_for("historial_ventas", venta_id=v_match.id))
        v_match = (
            venta_q
            .outerjoin(Cliente, Venta.cliente_id == Cliente.id)
            .filter(
                or_(
                    Venta.notas.ilike(term_like),
                    Cliente.nombre.ilike(term_like)
                )
            )
            .first()
        )
        if v_match:
            return redirect(url_for("historial_ventas", q=term))

    # 4) Crédito (admin/cobrador)
    if rol in ["admin", "cobrador"]:
        cr_match = (
            Credito.query
            .join(Cliente, Credito.cliente_id == Cliente.id)
            .filter(
                or_(
                    Credito.codigo.ilike(term_like),
                    Cliente.nombre.ilike(term_like),
                    Cliente.telefono.ilike(term_like)
                )
            )
            .first()
        )
        if cr_match:
            return redirect(url_for("cobranzas", credito_id=cr_match.id, filtro="todos"))

    # Fallback por rol
    if rol in ["admin", "vendedor"]:
        return redirect(url_for("punto_venta", categoria="Todas", q=term))
    if rol == "bodega":
        return redirect(url_for("admin", q=term))
    if rol == "cobrador":
        return redirect(url_for("cobranzas", q=term, filtro="todos"))
    return redirect(url_for("index"))

@app.route("/busqueda_global")
@login_required
def busqueda_global():
    q = (request.args.get("q") or "").strip()
    like = f"%{q}%"
    q_num = parse_non_negative_int(q)
    rol = session.get("rol")

    productos = []
    clientes_res = []
    ventas_res = []
    creditos_res = []
    usuarios_res = []

    if q:
        productos = (
            Producto.query
            .outerjoin(Categoria, Producto.categoria_id == Categoria.id)
            .filter(
                Producto.is_deleted == False,
                Producto.activo == True,
                or_(
                    Producto.nombre.ilike(like),
                    Producto.descripcion.ilike(like),
                    Categoria.nombre.ilike(like)
                )
            )
            .order_by(Producto.nombre.asc())
            .limit(20)
            .all()
        )

        if rol != "bodega":
            clientes_res = (
                Cliente.query
                .filter(
                    or_(
                        Cliente.nombre.ilike(like),
                        Cliente.telefono.ilike(like),
                        Cliente.documento.ilike(like),
                        Cliente.direccion.ilike(like),
                        Cliente.email.ilike(like),
                        Cliente.notas.ilike(like)
                    )
                )
                .order_by(Cliente.nombre.asc())
                .limit(20)
                .all()
            )

            filtros_venta = [
                Venta.estado.ilike(like),
                Venta.metodo_pago.ilike(like),
                Venta.notas.ilike(like),
                Cliente.nombre.ilike(like),
                Cliente.telefono.ilike(like),
                Usuario.username.ilike(like)
            ]
            if q_num is not None:
                filtros_venta.append(Venta.id == q_num)

            ventas_res = (
                Venta.query
                .outerjoin(Cliente, Venta.cliente_id == Cliente.id)
                .outerjoin(Usuario, Venta.vendedor_id == Usuario.id)
                .filter(Venta.cerrado == True)
                .filter(or_(*filtros_venta))
                .order_by(Venta.fecha_cierre.desc())
                .limit(20)
                .all()
            )

            filtros_credito = [
                Credito.codigo.ilike(like),
                Credito.estado.ilike(like),
                Credito.observaciones.ilike(like),
                Cliente.nombre.ilike(like),
                Cliente.telefono.ilike(like)
            ]
            if q_num is not None:
                filtros_credito.append(Credito.id == q_num)
                filtros_credito.append(Credito.venta_id == q_num)

            creditos_res = (
                Credito.query
                .join(Cliente, Credito.cliente_id == Cliente.id)
                .filter(or_(*filtros_credito))
                .order_by(Credito.fecha_inicio.desc())
                .limit(20)
                .all()
            )

            if rol == "admin":
                usuarios_res = (
                    Usuario.query
                    .outerjoin(Sede, Usuario.sede_id == Sede.id)
                    .filter(
                        or_(
                            Usuario.username.ilike(like),
                            Usuario.rol.ilike(like),
                            Sede.nombre.ilike(like)
                        )
                    )
                    .order_by(Usuario.username.asc())
                    .limit(20)
                    .all()
                )

    return render_template(
        "busqueda_global.html",
        q=q,
        productos=productos,
        clientes_res=clientes_res,
        ventas_res=ventas_res,
        creditos_res=creditos_res,
        usuarios_res=usuarios_res,
        rol=rol
    )

@app.route("/busqueda_globa")
@login_required
def busqueda_globa_alias():
    # Compatibilidad con enlaces anteriores que quedaron sin la "l" final.
    return redirect(url_for("busqueda_global", q=(request.args.get("q") or "").strip()))

# ==========================
# PUNTO DE VENTA (POS)
# ==========================
@app.route("/punto_venta", methods=["GET", "POST"])
@login_required
def punto_venta():
    if session.get("rol") not in ["admin", "vendedor"]:
        flash("Tu rol no tiene acceso al modulo de ventas.", "warning")
        return redirect(url_for("index"))

    sede_id = session.get("sede_id")
    if not sede_id and session.get("rol") != "admin":
        flash("Tu usuario no tiene una sede asignada.", "warning")
        return redirect(url_for("login"))
    
    # Validar si no hay sede_id, usar la primera sede activa (para admin)
    if not sede_id:
        primera_sede = Sede.query.filter_by(activa=True).first()
        if primera_sede:
            sede_id = primera_sede.id
        else:
            flash("No hay sedes activas en el sistema.", "danger")
            return redirect(url_for("login"))

    sede = Sede.query.get(sede_id)
    if not sede:
        flash("La sede seleccionada no existe o no esta activa.", "warning")
        session.pop("sede_id", None)
        return redirect(url_for("index"))
    
    # Obtener o crear una venta abierta para este vendedor en esta sede
    venta = Venta.query.filter_by(vendedor_id=session["user_id"], sede_id=sede_id, cerrado=False).first()
    
    if request.method == "POST":
        if not venta:
            venta = Venta(vendedor_id=session["user_id"], sede_id=sede_id)
            db.session.add(venta)
            db.session.flush()
            
        prod_id = request.form.get("producto_id")
        if prod_id:
            prod = db.session.get(Producto, prod_id)
            if prod and prod.activo and not prod.is_deleted:
                notas = request.form.get("notas", "").strip()
                p_unit = prod.precio
                cant = parse_non_negative_int(request.form.get("cantidad", 1))
                if cant is None or cant <= 0:
                    flash("Cantidad invalida para agregar al carrito.", "warning")
                    return redirect(request.referrer or url_for("punto_venta"))
                stock_actual, _ = obtener_stock_producto_sede(prod.id, sede_id)
                cantidad_actual_en_venta = sum(i.cantidad for i in venta.items if i.producto_id == prod.id)
                if cantidad_actual_en_venta + cant > stock_actual:
                    flash(f"Stock insuficiente para {prod.nombre}. Disponible: {stock_actual}.", "warning")
                    return redirect(request.referrer or url_for("punto_venta"))
                existe = DetalleVenta.query.filter_by(venta_id=venta.id, producto_id=prod.id, notas=notas).first()
                if existe:
                    existe.cantidad += cant
                else:
                    db.session.add(DetalleVenta(venta_id=venta.id, producto_id=prod.id, cantidad=cant, precio_unitario=p_unit, notas=notas))
                recalcular_total_venta(venta)
                db.session.commit()
            else:
                flash("El producto no esta disponible para venta.", "warning")
        return redirect(url_for(
            "punto_venta",
            categoria=request.args.get('categoria', 'Salas'),
            q=request.args.get("q", "")
        ))

    search_q = (request.args.get("q") or "").strip()
    prods_query = (
        Producto.query
        .filter(Producto.activo == True, Producto.is_deleted == False)
        .outerjoin(Categoria, Producto.categoria_id == Categoria.id)
    )
    prods = prods_query.all()
    if search_q:
        qn = normalizar_busqueda(search_q)
        prods_filtrados = []
        for p in prods:
            texto = " ".join([
                p.nombre or "",
                p.descripcion or "",
                p.categoria_rel.nombre if p.categoria_rel else ""
            ])
            if qn in normalizar_busqueda(texto):
                prods_filtrados.append(p)
        prods = prods_filtrados
    cats_query = Categoria.query.all()
    cats = sorted([c.nombre for c in cats_query])
    
    all_clientes = Cliente.query.order_by(Cliente.nombre).all()
    if venta:
        total_prev = venta.total or 0
        total_calc = recalcular_total_venta(venta)
        if total_calc != total_prev:
            db.session.commit()

    items_agrupados = agrupar_items_venta(venta)
    total_display = sum((it.get("precio", 0) or 0) * (it.get("cantidad", 0) or 0) for it in items_agrupados)

    cliente_deuda = 0
    cliente_credito_activo = None
    if venta and venta.cliente_id:
        cliente_deuda = sincronizar_cartera_cliente(venta.cliente_id)
        cliente_credito_activo = obtener_credito_activo_cliente(venta.cliente_id)
        db.session.commit()

    categoria_actual = request.args.get('categoria', cats[0] if cats else 'General')
    if search_q:
        categoria_actual = 'Todas'

    return render_template("pos.html", venta=venta, items_agrupados=items_agrupados, 
                           productos=prods, categorias=cats, 
                           categoria_actual=categoria_actual, 
                           clientes=all_clientes, sede=sede,
                           total_display=total_display,
                           cliente_deuda=cliente_deuda,
                           cliente_credito_activo=cliente_credito_activo,
                           search_q=search_q)

@app.route("/actualizar_info_venta", methods=["POST"])
@login_required
def actualizar_info_venta():
    vid = request.form.get("venta_id")
    v = db.session.get(Venta, vid) if vid else None
    if not v:
        sede_id = session.get("sede_id")
        if not sede_id:
            primera_sede = Sede.query.filter_by(activa=True).first()
            sede_id = primera_sede.id if primera_sede else None
        if not sede_id:
            flash("No se pudo determinar la sede para asociar el cliente.", "warning")
            return redirect(request.referrer or url_for("punto_venta"))
        v = Venta.query.filter_by(vendedor_id=session["user_id"], sede_id=sede_id, cerrado=False).first()
        if not v:
            v = Venta(vendedor_id=session["user_id"], sede_id=sede_id)
            db.session.add(v)
            db.session.flush()
    if not venta_editable_por_usuario(v):
        flash("No tienes permisos para editar esta venta.", "danger")
        return redirect(request.referrer or url_for("punto_venta"))
    
    cliente_id = parse_non_negative_int(request.form.get("cliente_id"))
    tel = normalizar_telefono(request.form.get("telefono"))
    nom = (request.form.get("nombre") or "").strip()
    ape = (request.form.get("apellido") or "").strip()
    doc = normalizar_documento(request.form.get("documento"))
    email = (request.form.get("email") or "").strip()
    notas_cliente = (request.form.get("notas") or "").strip()
    dir = (request.form.get("direccion") or "").strip()

    c = None
    creado_en_esta_operacion = False

    if cliente_id:
        c = db.session.get(Cliente, cliente_id)
        if not c:
            flash("El cliente seleccionado no existe.", "warning")
            return redirect(request.referrer or url_for("punto_venta"))
        if nom:
            c.nombre = nom
        if ape:
            c.apellido = ape
        if dir:
            c.direccion = dir
        if email:
            c.email = email
        if notas_cliente:
            c.notas = notas_cliente
        if doc:
            doc_colision = Cliente.query.filter(Cliente.documento == doc, Cliente.id != c.id).first()
            if doc_colision:
                flash("La cédula/NIT ya existe en otro cliente. No se actualizó ese dato.", "warning")
            else:
                c.documento = doc
        if tel and len(tel) >= 7:
            # Si el telefono ya existe en otro cliente, no bloquear:
            # asociar directamente ese cliente para evitar friccion en venta.
            otro = Cliente.query.filter(Cliente.telefono == tel, Cliente.id != c.id).first()
            if otro:
                c = otro
                if nom:
                    c.nombre = nom
                if ape:
                    c.apellido = ape
                if dir:
                    c.direccion = dir
                if email:
                    c.email = email
                if notas_cliente:
                    c.notas = notas_cliente
                if doc and not c.documento:
                    c.documento = doc
                flash("El telefono ya existia, se asigno el cliente registrado con ese numero.", "info")
            else:
                c.telefono = tel
    else:
        if not tel or len(tel) < 7:
            flash("Selecciona un cliente existente o escribe un teléfono válido para crear/buscar.", "warning")
            return redirect(request.referrer or url_for("punto_venta"))

        c = Cliente.query.filter_by(telefono=tel).first()
        if not c:
            if doc:
                c = Cliente.query.filter_by(documento=doc).first()
            c = Cliente(
                nombre=nom or f"Cliente {tel[-4:]}",
                apellido=ape or None,
                telefono=tel,
                documento=doc or None,
                direccion=dir or None,
                email=email or None,
                notas=notas_cliente or None
            ) if not c else c
            if db.session.object_session(c) is None:
                db.session.add(c)
                creado_en_esta_operacion = True
            else:
                if nom:
                    c.nombre = nom
                if ape:
                    c.apellido = ape
                if dir:
                    c.direccion = dir
                if email:
                    c.email = email
                if notas_cliente:
                    c.notas = notas_cliente
                if tel and len(tel) >= 7:
                    c.telefono = tel
                flash("La cédula/NIT ya existía, se asignó ese cliente.", "info")
        else:
            if nom:
                c.nombre = nom
            if ape:
                c.apellido = ape
            if dir:
                c.direccion = dir
            if email:
                c.email = email
            if notas_cliente:
                c.notas = notas_cliente
            if doc:
                doc_colision = Cliente.query.filter(Cliente.documento == doc, Cliente.id != c.id).first()
                if doc_colision:
                    flash("La cédula/NIT ya existe en otro cliente. No se actualizó ese dato.", "warning")
                else:
                    c.documento = doc
    
    db.session.flush()
    v.cliente_id = c.id
    if dir:
        v.direccion_envio = dir
    elif c.direccion and not v.direccion_envio:
        v.direccion_envio = c.direccion
    deuda_cliente = sincronizar_cartera_cliente(c.id)
    db.session.commit()
    
    if creado_en_esta_operacion:
        flash(f"Cliente creado y asignado correctamente. Cartera actual: ${deuda_cliente:,.0f}", "success")
    else:
        flash(f"Cliente asignado correctamente. Cartera actual: ${deuda_cliente:,.0f}", "success")
    return redirect(request.referrer or url_for("punto_venta"))

@app.route("/api/cliente/<string:tel>")
@login_required
def api_cliente(tel):
    tel_limpio = normalizar_telefono(tel)
    c = Cliente.query.filter_by(telefono=tel_limpio).first()
    if c:
        deuda_actual = sincronizar_cartera_cliente(c.id)
        credito_activo = obtener_credito_activo_cliente(c.id)
        db.session.commit()
        return jsonify({
            "nombre": c.nombre,
            "apellido": c.apellido,
            "documento": c.documento,
            "direccion": c.direccion,
            "email": c.email,
            "notas": c.notas,
            "deuda": deuda_actual,
            "credito_activo": {
                "id": credito_activo.id,
                "codigo": credito_activo.codigo,
                "saldo": credito_activo.saldo_actual,
                "periodicidad": credito_activo.periodicidad,
            } if credito_activo else None
        })
    return jsonify({"error": "No encontrado"}), 404

@app.route("/api/pos/agregar_item", methods=["POST"])
@login_required
def api_agregar_item():
    vid = request.form.get("venta_id")
    v = db.session.get(Venta, vid) if vid else None
    
    if not v:
        sede_id = session.get("sede_id")
        if not sede_id:
            primera_sede = Sede.query.filter_by(activa=True).first()
            sede_id = primera_sede.id if primera_sede else None
        v = Venta(vendedor_id=session["user_id"], sede_id=sede_id)
        db.session.add(v)
        db.session.flush()
    elif not venta_editable_por_usuario(v):
        return jsonify({"status": "error", "message": "Venta no editable"}), 403

    prod_id = request.form.get("producto_id")
    if prod_id:
        prod = db.session.get(Producto, prod_id)
        if prod and prod.activo and not prod.is_deleted:
            notas = request.form.get("notas", "").strip()
            p_unit = prod.precio
            cant = parse_non_negative_int(request.form.get("cantidad", 1))
            if cant is None or cant <= 0:
                return jsonify({"status": "error", "message": "Cantidad invalida"}), 400
            stock_actual, _ = obtener_stock_producto_sede(prod.id, v.sede_id)
            cantidad_actual_en_venta = sum(i.cantidad for i in v.items if i.producto_id == prod.id)
            if cantidad_actual_en_venta + cant > stock_actual:
                return jsonify({"status": "error", "message": "Stock insuficiente"}), 400
            existe = DetalleVenta.query.filter_by(venta_id=v.id, producto_id=prod.id, notas=notas).first()
            if existe: 
                existe.cantidad += cant
            else: 
                db.session.add(DetalleVenta(venta_id=v.id, producto_id=prod.id, cantidad=cant, precio_unitario=p_unit, notas=notas))
            
            recalcular_total_venta(v)
            db.session.commit()
            return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Producto no disponible"}), 400

@app.route("/eliminar_item/<int:item_id>", methods=["POST"])
@login_required
def eliminar_item(item_id):
    d = db.session.get(DetalleVenta, item_id)
    if d:
        v = d.venta
        if not venta_editable_por_usuario(v):
            flash("No tienes permisos para modificar esta venta.", "danger")
            return redirect(request.referrer or url_for("punto_venta"))
        if d.cantidad > 1: 
            d.cantidad -= 1
        else: 
            db.session.delete(d)
        db.session.flush()
        
        if len(v.items) == 0:
            db.session.delete(v)
        else:
            recalcular_total_venta(v)
        db.session.commit()
    return redirect(request.referrer)

@app.route("/cancelar_venta/<int:venta_id>", methods=["POST"])
@login_required
def cancelar_venta(venta_id):
    v = Venta.query.get(venta_id)
    if v:
        if not venta_editable_por_usuario(v):
            flash("No tienes permisos para cancelar esta venta.", "danger")
            return redirect(request.referrer or url_for("punto_venta"))
        db.session.delete(v)
        db.session.commit()
    return redirect(url_for("punto_venta"))

@app.route("/cerrar_cuenta", methods=["POST"])
@login_required
def cerrar_cuenta():
    v = Venta.query.get(request.form.get("venta_id"))
    def redir_pos():
        return redirect(url_for("punto_venta"))

    if not v:
        return redir_pos()
    if not venta_editable_por_usuario(v):
        flash("No tienes permisos para cerrar esta venta.", "danger")
        return redir_pos()
    if not v.items:
        flash("La venta no tiene items para cerrar.", "warning")
        return redir_pos()
    
    try:
        def fail_checkout(reason, user_msg, cat="warning"):
            app.logger.warning(
                "cerrar_cuenta rechazado venta_id=%s reason=%s metodo=%s cliente_sel=%s tel=%s doc=%s",
                request.form.get("venta_id"),
                reason,
                request.form.get("metodo_pago"),
                request.form.get("credito_cliente_id"),
                request.form.get("credito_cliente_telefono"),
                request.form.get("credito_cliente_documento"),
            )
            flash(user_msg, cat)
            return redir_pos()

        def resolver_cliente_desde_form(obligatorio=False, contexto="venta"):
            cliente_sel_id = parse_non_negative_int(request.form.get("credito_cliente_id"))
            tel = normalizar_telefono(request.form.get("credito_cliente_telefono"))
            nom = (request.form.get("credito_cliente_nombre") or "").strip()
            ape = (request.form.get("credito_cliente_apellido") or "").strip()
            doc = normalizar_documento(request.form.get("credito_cliente_documento"))
            dire = (request.form.get("credito_cliente_direccion") or "").strip()
            correo = (request.form.get("credito_cliente_email") or "").strip()
            notas_cliente = (request.form.get("credito_cliente_notas") or "").strip()

            # Compatibilidad con campos del modal general de cliente.
            if not tel:
                tel = normalizar_telefono(request.form.get("telefono"))
            if not nom:
                nom = (request.form.get("nombre") or "").strip()
            if not ape:
                ape = (request.form.get("apellido") or "").strip()
            if not dire:
                dire = (request.form.get("direccion") or "").strip()
            if not doc:
                doc = normalizar_documento(request.form.get("documento"))
            if not correo:
                correo = (request.form.get("email") or "").strip()
            if not notas_cliente:
                notas_cliente = (request.form.get("notas") or "").strip()

            if obligatorio and not cliente_sel_id:
                if (not tel or len(tel) < 7) and not doc:
                    return None, False, f"Para {contexto} debes seleccionar cliente o ingresar teléfono válido / CC-NIT."
                if contexto in {"contado", "credito"}:
                    if not nom:
                        return None, False, f"En {contexto} debes ingresar el nombre del cliente."
                    if not dire:
                        return None, False, f"En {contexto} debes ingresar la dirección del cliente."
                if contexto == "credito":
                    if not ape:
                        return None, False, "En credito debes ingresar el apellido del cliente."
                    if not doc:
                        return None, False, "En credito debes ingresar la cédula o NIT del cliente."

            if not cliente_sel_id and not tel and not doc and not nom and not ape and not dire and not correo and not notas_cliente:
                return None, False, ""

            cliente_obj = None
            creado = False
            cliente_nuevo_tmp = None

            if cliente_sel_id:
                cliente_obj = db.session.get(Cliente, cliente_sel_id)
                if not cliente_obj:
                    return None, False, "El cliente seleccionado no existe."
            else:
                if tel:
                    cliente_obj = Cliente.query.filter_by(telefono=tel).first()
                if not cliente_obj and doc:
                    cliente_obj = Cliente.query.filter_by(documento=doc).first()
                if not cliente_obj:
                    cliente_obj = Cliente(
                        nombre=nom or (f"Cliente {tel[-4:]}" if tel else "Cliente"),
                        apellido=ape or None,
                        telefono=tel or None,
                        documento=doc or None,
                        direccion=dire or None,
                        email=correo or None,
                        notas=notas_cliente or None
                    )
                    db.session.add(cliente_obj)
                    creado = True
                    cliente_nuevo_tmp = cliente_obj

            if tel and len(tel) >= 7:
                colision_tel = Cliente.query.filter(Cliente.telefono == tel, Cliente.id != cliente_obj.id).first()
                if colision_tel:
                    if cliente_sel_id:
                        # Si el usuario selecciono cliente manualmente, no bloquear venta:
                        # conservamos el cliente seleccionado y omitimos actualizar telefono duplicado.
                        tel = ""
                    else:
                        # Si no selecciono cliente y el telefono ya existe, asociar ese cliente existente.
                        if creado and cliente_nuevo_tmp is not None:
                            try:
                                db.session.expunge(cliente_nuevo_tmp)
                            except Exception:
                                pass
                            creado = False
                            cliente_nuevo_tmp = None
                        cliente_obj = colision_tel

            if doc:
                colision_doc = Cliente.query.filter(Cliente.documento == doc, Cliente.id != cliente_obj.id).first()
                if colision_doc:
                    if cliente_sel_id:
                        # No bloquear venta por CC/NIT duplicado cuando ya se eligio cliente.
                        doc = ""
                    else:
                        if creado and cliente_nuevo_tmp is not None:
                            try:
                                db.session.expunge(cliente_nuevo_tmp)
                            except Exception:
                                pass
                            creado = False
                            cliente_nuevo_tmp = None
                        cliente_obj = colision_doc

            if nom:
                cliente_obj.nombre = nom
            if ape:
                cliente_obj.apellido = ape
            if dire:
                cliente_obj.direccion = dire
            if tel and len(tel) >= 7:
                cliente_obj.telefono = tel
            if doc:
                cliente_obj.documento = doc
            if correo:
                cliente_obj.email = correo
            if notas_cliente:
                cliente_obj.notas = notas_cliente

            return cliente_obj, creado, ""

        metodo = request.form.get("metodo_pago")
        metodo_ui = request.form.get("metodo_pago_ui")
        modo_credito_flag = request.form.get("modo_credito_activo")
        metodos_validos = {"Efectivo", "Tarjeta", "Transferencia", "Credito", "Mixto", "Cotizacion"}
        if metodo == "Credito" and modo_credito_flag == "0" and metodo_ui in metodos_validos and metodo_ui != "Credito":
            metodo = metodo_ui
        if metodo not in metodos_validos:
            return fail_checkout("metodo_invalido", "Metodo de pago no valido.", "danger")
        if metodo == "Credito":
            app.logger.info(
                "POST credito venta_id=%s cliente_id=%s tel=%s doc=%s nombre=%s direccion=%s",
                request.form.get("venta_id"),
                request.form.get("credito_cliente_id"),
                request.form.get("credito_cliente_telefono"),
                request.form.get("credito_cliente_documento"),
                request.form.get("credito_cliente_nombre"),
                request.form.get("credito_cliente_direccion"),
            )

        total_original_venta = int(v.total or 0)
        descuento_contado = 0
        total_contado_manual_raw = (request.form.get("total_contado_manual") or "").strip()
        if metodo in {"Efectivo", "Tarjeta", "Transferencia"} and total_contado_manual_raw:
            total_contado_manual = parse_non_negative_int(total_contado_manual_raw)
            if total_contado_manual is None or total_contado_manual <= 0:
                return fail_checkout("total_contado_invalido", "El precio final contado debe ser un numero valido mayor a cero.", "warning")
            if total_contado_manual > total_original_venta:
                return fail_checkout(
                    "total_contado_mayor_original",
                    "El precio final contado no puede ser mayor al total original de la venta.",
                    "warning"
                )
            descuento_contado = max(total_original_venta - total_contado_manual, 0)
            v.total = total_contado_manual

        notas_base = (request.form.get("notas_venta", "") or "").strip()
        if descuento_contado > 0:
            nota_descuento = f"Descuento contado aplicado: ${descuento_contado:,.0f} (total original: ${total_original_venta:,.0f})"
            notas_base = f"{notas_base}\n{nota_descuento}".strip() if notas_base else nota_descuento
        v.notas = notas_base
        direccion_envio = request.form.get("direccion_envio", "").strip()
        if direccion_envio:
            v.direccion_envio = direccion_envio
        
        if metodo == "Cotizacion":
            if request.form.get("cotizacion_plan") == "1":
                periodicidad_cot = (request.form.get("periodicidad_credito") or "Mensual").title()
                if periodicidad_cot not in ["Semanal", "Quincenal", "Mensual"]:
                    periodicidad_cot = "Mensual"

                numero_cuotas_cot = parse_non_negative_int(request.form.get("numero_cuotas")) or 1
                numero_cuotas_cot = max(1, min(numero_cuotas_cot, 120))
                cuota_inicial_cot = parse_non_negative_int(request.form.get("cuota_inicial") or 0) or 0
                saldo_financiar_cot = max(int(v.total or 0) - cuota_inicial_cot, 0)
                pct_interes_cot = 0.0
                valor_interes_cot = 0
                total_financiado_cot = saldo_financiar_cot + valor_interes_cot
                valor_cuota_cot = int(math.ceil(total_financiado_cot / numero_cuotas_cot)) if numero_cuotas_cot > 0 else total_financiado_cot
                fecha_inicio_cot = (request.form.get("fecha_inicio_credito", "") or "").strip()
                resumen_cot = (request.form.get("resumen_cotizacion", "") or "").strip()

                if not resumen_cot:
                    resumen_cot = (
                        "Cotizacion en cuotas:\n"
                        f"Cuota inicial: ${cuota_inicial_cot:,.0f}\n"
                        f"Frecuencia: {periodicidad_cot}\n"
                        f"Numero cuotas: {numero_cuotas_cot}\n"
                        f"Fecha inicio: {fecha_inicio_cot or 'No definida'}\n"
                        f"Saldo a financiar: ${saldo_financiar_cot:,.0f}\n"
                        f"Total financiado: ${total_financiado_cot:,.0f}\n"
                        f"Valor por cuota: ${valor_cuota_cot:,.0f}"
                    )

                notas_cotizacion = f"{notas_base}\n\n{resumen_cot}".strip() if notas_base else resumen_cot
            else:
                notas_cotizacion = notas_base or (v.notas or "")

            # Modo cotizacion pura: no cerrar venta, no descontar inventario.
            session["cotizacion_preview"] = {
                "venta_id": v.id,
                "notas": notas_cotizacion,
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }
            registrar_auditoria("Cotización", f"Cotización preview de venta abierta #{v.id} por {v.total}")
            flash("Cotización generada en PDF sin descontar inventario.", "success")
            return redirect(url_for("imprimir_ticket", venta_id=v.id, cotizacion=1, preview=1))

        # Validación de montos
        efectivo = parse_non_negative_int(request.form.get("pago_efectivo") or 0)
        tarjeta = parse_non_negative_int(request.form.get("pago_tarjeta") or 0)
        transf = parse_non_negative_int(request.form.get("pago_transferencia") or 0)
        recibido = parse_non_negative_int(request.form.get("monto_recibido") or 0)
        if any(x is None for x in [efectivo, tarjeta, transf, recibido]):
            return fail_checkout("montos_invalidos", "Error: Los montos deben ser valores numéricos.", "danger")
        
        if metodo == "Efectivo":
            efectivo, tarjeta, transf = recibido, 0, 0
        elif metodo == "Tarjeta":
            efectivo, tarjeta, transf = 0, recibido, 0
        elif metodo == "Transferencia":
            efectivo, tarjeta, transf = 0, 0, recibido
        elif metodo == "Mixto":
            recibido = efectivo + tarjeta + transf
            if recibido <= 0:
                return fail_checkout("mixto_cero", "En pago mixto debes registrar al menos un monto mayor a cero.", "warning")
        elif metodo == "Credito":
            efectivo, tarjeta, transf = 0, 0, 0
            cuota_inicial_form = parse_non_negative_int(request.form.get("cuota_inicial") or 0) or 0
            recibido = min(cuota_inicial_form, int(v.total or 0))
            
        v.pago_efectivo = efectivo
        v.pago_tarjeta = tarjeta
        v.pago_transferencia = transf
        v.monto_recibido = recibido
        
        faltante = max((v.total or 0) - recibido, 0)

        if metodo == "Credito" and faltante <= 0:
            return fail_checkout("credito_sin_saldo", "Para registrar crédito, la cuota inicial debe ser menor al total de la venta.", "warning")

        cliente_sel_id_post = parse_non_negative_int(request.form.get("credito_cliente_id"))
        tel_cliente_post = normalizar_telefono(request.form.get("credito_cliente_telefono"))
        nom_cliente_post = (request.form.get("credito_cliente_nombre") or "").strip()
        ape_cliente_post = (request.form.get("credito_cliente_apellido") or "").strip()
        doc_cliente_post = normalizar_documento(request.form.get("credito_cliente_documento"))
        dir_cliente_post = (request.form.get("credito_cliente_direccion") or "").strip()
        email_cliente_post = (request.form.get("credito_cliente_email") or "").strip()
        notas_cliente_post = (request.form.get("credito_cliente_notas") or "").strip()
        hay_datos_cliente_form = bool(
            cliente_sel_id_post or tel_cliente_post or nom_cliente_post or ape_cliente_post or doc_cliente_post or dir_cliente_post or email_cliente_post or notas_cliente_post
        )

        # Evitar cruce involuntario: solo el metodo "Credito" puede dejar faltante.
        if metodo in {"Efectivo", "Tarjeta", "Transferencia", "Mixto"} and faltante > 0:
            return fail_checkout(
                "pago_insuficiente_no_credito",
                "El monto recibido no cubre el total. Completa el pago o usa el boton Credito.",
                "warning"
            )

        # Cliente obligatorio solo en credito.
        # En contado es opcional, pero si diligencian datos se guarda y vincula.
        requiere_cliente = metodo == "Credito" or hay_datos_cliente_form
        if requiere_cliente:
            cliente_obligatorio = metodo == "Credito"
            cliente_ctx = "credito" if metodo == "Credito" else "contado"
            cliente_form, cliente_creado, error_cliente = resolver_cliente_desde_form(obligatorio=cliente_obligatorio, contexto=cliente_ctx)
            if error_cliente:
                return fail_checkout("cliente_invalido", error_cliente, "warning")
            if cliente_form:
                db.session.flush()
                v.cliente_id = cliente_form.id
                direccion_form = (request.form.get("credito_cliente_direccion") or "").strip()
                if direccion_form:
                    v.direccion_envio = direccion_form
                elif cliente_form.direccion and not v.direccion_envio:
                    v.direccion_envio = cliente_form.direccion
                if cliente_creado:
                    flash("Cliente creado y vinculado a la venta.", "success")

        nuevo_credito = None
        if metodo == "Credito" and faltante > 0:
            if not v.cliente_id:
                return fail_checkout("cliente_no_asociado", "No fue posible asociar cliente a la venta antes de generar cartera.", "warning")
            periodicidad_credito = (request.form.get("periodicidad_credito") or "Mensual").title()
            if periodicidad_credito not in ["Semanal", "Quincenal", "Mensual"]:
                periodicidad_credito = "Mensual"
            conf_dias = Configuracion.query.first() or Configuracion()
            opts_map = opciones_dia_pago_desde_config(conf_dias)
            opts_periodo = opts_map.get(periodicidad_credito, [])
            pares_validos = []
            for op in opts_periodo:
                try:
                    pares_validos.append((int(str(op.get("value"))), str(op.get("label") or op.get("value"))))
                except Exception:
                    pass
            if not pares_validos:
                defs = opciones_dia_pago_default()
                for op in defs.get(periodicidad_credito, []):
                    try:
                        pares_validos.append((int(str(op.get("value"))), str(op.get("label") or op.get("value"))))
                    except Exception:
                        pass
            if not pares_validos:
                pares_validos = [(1, "Dia 1")]
            valores_validos = {v for v, _ in pares_validos}
            etiqueta_map = {v: l for v, l in pares_validos}

            if periodicidad_credito == "Quincenal":
                dia_pago_credito_1 = parse_non_negative_int(request.form.get("dia_pago_credito_1"))
                dia_pago_credito_2 = parse_non_negative_int(request.form.get("dia_pago_credito_2"))
                dias_quincenales = []
                for candidato in [dia_pago_credito_1, dia_pago_credito_2]:
                    if candidato in valores_validos and candidato not in dias_quincenales:
                        dias_quincenales.append(candidato)
                if len(dias_quincenales) == 1:
                    unico = dias_quincenales[0]
                    ordenados = sorted(valores_validos)
                    indice = ordenados.index(unico) if unico in ordenados else -1
                    candidatos_extra = ordenados[indice + 1:] + ordenados[:indice]
                    for candidato_extra in candidatos_extra:
                        if candidato_extra != unico:
                            dias_quincenales.append(candidato_extra)
                            break
                for valor_defecto, _ in pares_validos:
                    if len(dias_quincenales) >= 2:
                        break
                    if valor_defecto not in dias_quincenales:
                        dias_quincenales.append(valor_defecto)
                dias_quincenales = sorted(dias_quincenales[:2])
                dia_pago_credito = dias_quincenales
                dia_pago_texto = " y ".join(etiqueta_map.get(dia, f"Dia {dia}") for dia in dias_quincenales)
            else:
                dia_pago_credito = parse_non_negative_int(request.form.get("dia_pago_credito"))
                if dia_pago_credito not in valores_validos:
                    dia_pago_credito = pares_validos[0][0]
                dia_pago_texto = etiqueta_map.get(dia_pago_credito, f"Dia {dia_pago_credito}")
            numero_cuotas = parse_non_negative_int(request.form.get("numero_cuotas")) or 1
            numero_cuotas = max(1, min(numero_cuotas, 120))
            cliente_credito_ref = db.session.get(Cliente, v.cliente_id)
            if not cliente_credito_ref:
                return fail_checkout("cliente_no_encontrado", "No se encontro el cliente para registrar la cartera.", "warning")

            cuota_inicial = parse_non_negative_int(request.form.get("cuota_inicial") or 0) or 0
            fecha_inicio_str = request.form.get("fecha_inicio_credito", "")
            try:
                fecha_inicio_pago = datetime.strptime(fecha_inicio_str, "%Y-%m-%d")
            except Exception:
                fecha_inicio_pago = datetime.now()

            monto_total_venta = int(v.total or 0)
            saldo_financiar = max(monto_total_venta - cuota_inicial, 0)

            pct_interes = 0.0
            valor_interes = 0
            total_financiado = saldo_financiar + valor_interes
            valor_cuota_calc = int(math.ceil(total_financiado / numero_cuotas)) if numero_cuotas > 0 else total_financiado

            cliente_credito_ref.deuda = (cliente_credito_ref.deuda or 0) + int(total_financiado)
            db.session.add(MovimientoCredito(
                cliente_id=v.cliente_id,
                tipo='cargo',
                monto=int(total_financiado),
                nota=f"Credito Venta #{v.id} | CI ${cuota_inicial:,.0f}",
                usuario_id=session.get("user_id")
            ))
            obs_credito = (request.form.get("observaciones_credito") or "").strip()
            encabezado_dia = f"Dia de pago ({periodicidad_credito}): {dia_pago_texto}"
            obs_credito = f"{encabezado_dia}\n{obs_credito}".strip() if obs_credito else encabezado_dia
            referencias = []
            referencias_struct = []
            agregar_referencias_credito = (request.form.get("agregar_referencias_credito") or "").strip() in {"1", "true", "on", "yes"}
            if agregar_referencias_credito:
                referencias_requeridas = [1]
                ref2_tiene_datos = any((request.form.get(campo) or "").strip() for campo in ("ref2_nombre", "ref2_parentesco", "ref2_celular", "ref2_direccion"))
                if ref2_tiene_datos:
                    referencias_requeridas.append(2)

                for idx in referencias_requeridas:
                    ref_nombre = (request.form.get(f"ref{idx}_nombre") or "").strip()
                    ref_parentesco = (request.form.get(f"ref{idx}_parentesco") or "").strip()
                    ref_celular = (request.form.get(f"ref{idx}_celular") or "").strip()
                    ref_direccion = (request.form.get(f"ref{idx}_direccion") or "").strip()
                    cel_norm = normalizar_telefono(ref_celular)
                    if not ref_nombre or len(cel_norm) < 7:
                        etiqueta = "la referencia 1" if idx == 1 else f"la referencia {idx}"
                        return fail_checkout(
                            "referencias_incompletas",
                            f"Si activas referencias, debes completar {etiqueta} con nombre y celular valido.",
                            "warning"
                        )
                    referencias_struct.append({
                        "orden": idx,
                        "nombre": ref_nombre,
                        "parentesco": ref_parentesco,
                        "celular": cel_norm,
                        "direccion": ref_direccion
                    })
                    referencias.append(
                        f"Referencia {idx}: "
                        f"Nombre={ref_nombre or 'N/A'} | "
                        f"Parentesco={ref_parentesco or 'N/A'} | "
                        f"Celular={cel_norm or 'N/A'} | "
                        f"Direccion={ref_direccion or 'N/A'}"
                    )
            if referencias:
                encabezado_ref = "Referencias personales:"
                detalle_ref = "\n".join(referencias)
                obs_credito = f"{obs_credito}\n\n{encabezado_ref}\n{detalle_ref}".strip()
            obs_credito = f"{obs_credito}\n\nCredito generado desde venta #{v.id}".strip()
            nuevo_credito = Credito(
                codigo=generar_codigo_credito(),
                cliente_id=v.cliente_id,
                venta_id=v.id,
                periodicidad=periodicidad_credito,
                numero_cuotas=numero_cuotas,
                monto_total=monto_total_venta,
                cuota_inicial=cuota_inicial,
                saldo_financiar=saldo_financiar,
                porcentaje_interes=pct_interes,
                valor_interes=valor_interes,
                total_financiado=total_financiado,
                valor_cuota=valor_cuota_calc,
                saldo_actual=total_financiado,
                estado="Activo",
                observaciones=obs_credito
            )
            db.session.add(nuevo_credito)
            db.session.flush()

            # Persistir referencias personales en tabla dedicada para historial completo.
            for ref in referencias_struct:
                ref_row = ReferenciaCliente.query.filter_by(
                    cliente_id=v.cliente_id,
                    orden=ref["orden"]
                ).first()
                if not ref_row:
                    ref_row = ReferenciaCliente(cliente_id=v.cliente_id, orden=ref["orden"])
                    db.session.add(ref_row)
                ref_row.credito_id = nuevo_credito.id
                ref_row.nombre = ref["nombre"]
                ref_row.celular = ref["celular"]
                ref_row.parentesco = ref["parentesco"] or None
                ref_row.direccion = ref["direccion"] or None

            generar_plan_pagos(nuevo_credito, fecha_inicio_pago, dia_pago_credito, 1, saldo_objetivo=int(total_financiado))
            db.session.flush()
            sincronizar_cartera_cliente(v.cliente_id)

        # Blindaje: nunca cerrar una venta a crédito sin cliente/registro de crédito.
        if metodo == "Credito":
            if not v.cliente_id:
                return fail_checkout("credito_sin_cliente", "No se pudo asociar el cliente del crédito. Revisa los datos del cliente.", "warning")
            if not nuevo_credito and faltante > 0:
                return fail_checkout("credito_no_generado", "No se pudo generar la cartera del crédito. Intenta de nuevo.", "warning")

        ok_stock, msg_stock = validar_stock_venta(v)
        if not ok_stock:
            return fail_checkout("stock_insuficiente", msg_stock, "danger")
        
        v.cerrado = True
        v.fecha_cierre = datetime.now()
        v.metodo_pago = metodo
        v.cambio = recibido - v.total if recibido > v.total else 0
        v.estado = 'A Crédito' if (metodo == "Credito" and faltante > 0) else 'Pagada'
        v.estado_entrega = 'Pendiente'
        
        # Deduct stock & Kardex
        for item in v.items:
            inv = InventarioSede.query.filter_by(producto_id=item.producto_id, sede_id=v.sede_id).first()
            old_stock = inv.cantidad if inv else 0
            
            if inv:
                if inv.cantidad < item.cantidad:
                    raise ValueError(f"Stock insuficiente para {item.producto.nombre}.")
                inv.cantidad -= item.cantidad
            else:
                raise ValueError(f"No existe inventario configurado para {item.producto.nombre} en esta sede.")
            
            db.session.add(MovimientoInventario(
                producto_id=item.producto_id,
                sede_id=v.sede_id,
                tipo='SALIDA',
                cantidad=item.cantidad,
                stock_anterior=old_stock,
                stock_nuevo=inv.cantidad,
                usuario_id=session.get("user_id"),
                referencia=f"Venta #{v.id}"
            ))
                
        db.session.commit()
        app.logger.info(
            "cerrar_cuenta ok venta_id=%s metodo=%s cliente_id=%s total=%s recibido=%s faltante=%s",
            v.id, metodo, v.cliente_id, v.total, recibido, faltante
        )
        registrar_auditoria("Venta", f"Cierre de Venta #{v.id} - Total: {v.total} - Metodo: {v.metodo_pago}")
        return redirect(url_for("punto_venta", last_venta_id=v.id))

    except Exception as e:
        db.session.rollback()
        print(f"Error en cerrar_cuenta: {e}")
        app.logger.exception("Fallo en cerrar_cuenta para venta_id=%s", request.form.get("venta_id"))
        flash(f"Error al procesar la venta: {str(e)}", "danger")
        return redirect(url_for("punto_venta"))

# ==========================
# GESTIÓN LOGÍSTICA
# ==========================
@app.route("/logistica")
@login_required
def logistica():
    if session.get("rol") not in ["admin", "bodega"]:
        flash("Acceso denegado: Se requieren permisos de Logística/Admin.", "danger")
        return redirect(url_for("index"))
        
    sede_id = request.args.get('sede_id')
    if not sede_id:
        sede_id = session.get('sede_id')
    
    # Solo ventas cerradas que no sean cotizaciones
    query = Venta.query.filter(Venta.estado != 'cotización', Venta.cerrado == True)
    if sede_id:
        query = query.filter_by(sede_id=sede_id)
    
    # Mostrar ventas con entrega pendiente o en ruta
    ventas = query.filter(Venta.estado_entrega.in_(['Pendiente', 'En Ruta'])).order_by(Venta.fecha_cierre.desc()).all()
    sedes = Sede.query.filter_by(activa=True).all()
    
    return render_template("logistica.html", ventas=ventas, sedes=sedes, sede_actual=str(sede_id))

@app.route("/api/logistica_estado", methods=["POST"])
@login_required
def api_logistica_estado():
    if session.get("rol") not in ["admin", "bodega"]:
        return jsonify({"status": "error", "message": "No autorizado"}), 403
        
    venta_id = request.form.get('venta_id')
    nuevo_estado = request.form.get('estado_entrega')
    v = db.session.get(Venta, venta_id)
    if v:
        v.estado_entrega = nuevo_estado
        db.session.commit()
        registrar_auditoria("Logística", f"Despacho Venta #{venta_id} actualizado a {nuevo_estado}")
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Venta no encontrada"}), 404


# ==========================
# COBRANZAS (COBRADOR)
# ==========================
@app.route("/cobranzas")
@cobrador_required
def cobranzas():
    actualizar_estados_cuotas()
    sincronizar_cartera_global()
    db.session.commit()

    hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    manana = hoy + timedelta(days=1)
    tres_dias = hoy + timedelta(days=3)
    siete_dias = hoy + timedelta(days=7)

    # Estadisticas del dia
    cuotas_hoy = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= hoy,
        CuotaCredito.fecha_vencimiento < manana,
        CuotaCredito.estado.in_(["Pendiente", "Vence hoy"])
    ).all()
    total_cobrar_hoy = sum(c.saldo_pendiente for c in cuotas_hoy)

    cuotas_vencidas = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento < hoy,
        CuotaCredito.estado.in_(["Vencida", "Abonada"])
    ).all()
    total_vencido = sum(c.saldo_pendiente for c in cuotas_vencidas)

    pagos_hoy = AbonoCredito.query.filter(
        AbonoCredito.fecha >= hoy,
        AbonoCredito.fecha < manana
    ).all()
    total_pagos_hoy = sum(p.monto for p in pagos_hoy)

    proximas = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= tres_dias,
        CuotaCredito.estado == "Pendiente"
    ).all()
    total_proximas = sum(c.saldo_pendiente for c in proximas)

    proximas_semana = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= siete_dias,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).order_by(CuotaCredito.fecha_vencimiento.asc()).all()
    total_proximas_semana = sum(c.saldo_pendiente for c in proximas_semana)
    proximas_semana_preview = proximas_semana[:10]

    # Filtro activo
    filtro = request.args.get("filtro", "hoy")
    cliente_id_f = request.args.get("cliente_id")
    credito_id_f = request.args.get("credito_id")
    fecha_ini_f = request.args.get("fecha_ini")
    fecha_fin_f = request.args.get("fecha_fin")
    search_q = (request.args.get("q") or "").strip()

    q = CuotaCredito.query.join(Credito).join(Cliente)
    if filtro == "hoy":
        q = q.filter(CuotaCredito.fecha_vencimiento >= hoy, CuotaCredito.fecha_vencimiento < manana, CuotaCredito.estado.in_(["Pendiente", "Vence hoy"]))
    elif filtro == "vencidas":
        q = q.filter(CuotaCredito.fecha_vencimiento < hoy, ~CuotaCredito.estado.in_(["Pagada", "Cancelada"]))
    elif filtro == "proximas":
        q = q.filter(CuotaCredito.fecha_vencimiento >= manana, CuotaCredito.fecha_vencimiento <= tres_dias, CuotaCredito.estado == "Pendiente")
    elif filtro == "semana":
        q = q.filter(CuotaCredito.fecha_vencimiento >= manana, CuotaCredito.fecha_vencimiento <= siete_dias, ~CuotaCredito.estado.in_(["Pagada", "Cancelada"]))
    elif filtro == "activos":
        q = q.filter(Credito.estado == "Activo", ~CuotaCredito.estado.in_(["Pagada", "Cancelada"]))
    elif filtro == "pagados":
        q = q.filter(CuotaCredito.estado == "Pagada")
    elif filtro == "todos":
        pass # All quotas
        
    if cliente_id_f:
        q = q.filter(Credito.cliente_id == int(cliente_id_f))
    if credito_id_f:
        q = q.filter(Credito.id == int(credito_id_f))
    if fecha_ini_f:
        try:
            q = q.filter(CuotaCredito.fecha_vencimiento >= datetime.strptime(fecha_ini_f, "%Y-%m-%d"))
        except Exception:
            pass
    if fecha_fin_f:
        try:
            q = q.filter(CuotaCredito.fecha_vencimiento <= datetime.strptime(fecha_fin_f, "%Y-%m-%d").replace(hour=23, minute=59))
        except Exception:
            pass
    if search_q:
        like = f"%{search_q}%"
        q = q.filter(
            or_(
                Cliente.nombre.ilike(like),
                Cliente.telefono.ilike(like),
                Credito.codigo.ilike(like),
                Credito.estado.ilike(like)
            )
        )

    cuotas_tabla = q.order_by(CuotaCredito.fecha_vencimiento.asc()).all()

    clientes_lista = Cliente.query.order_by(Cliente.nombre).all()
    creditos_lista = Credito.query.order_by(Credito.fecha_inicio.desc()).all() # all credits for the filter dropdown
    
    ultimos_abonos = AbonoCredito.query.order_by(AbonoCredito.fecha.desc()).limit(20).all()

    return render_template(
        "cobranzas.html",
        clientes=clientes_lista,
        creditos=creditos_lista,
        cuotas_hoy=cuotas_hoy,
        total_cobrar_hoy=total_cobrar_hoy,
        cuotas_vencidas=cuotas_vencidas,
        total_vencido=total_vencido,
        total_pagos_hoy=total_pagos_hoy,
        proximas=proximas,
        total_proximas=total_proximas,
        proximas_semana=proximas_semana,
        total_proximas_semana=total_proximas_semana,
        proximas_semana_preview=proximas_semana_preview,
        cuotas_tabla=cuotas_tabla,
        filtro_activo=filtro,
        search_q=search_q,
        cliente_id_f=cliente_id_f,
        credito_id_f=credito_id_f,
        clientes_lista=clientes_lista,
        ultimos_abonos=ultimos_abonos
    )

@app.route("/abonar_cliente", methods=["POST"])
@login_required
def abonar_cliente():
    if session.get("rol") not in ["admin", "cobrador"]: 
        return redirect(url_for("index"))
    
    try:
        cid = request.form.get("cliente_id")
        credito_id = parse_non_negative_int(request.form.get("credito_id"))
        monto_str = request.form.get("monto_abono")
        nota = request.form.get("nota")
        
        try:
            monto = int(monto_str or 0)
        except ValueError:
            flash("Error: El monto del abono debe ser un valor numérico.", "danger")
            return redirect(request.referrer)

        c = db.session.get(Cliente, cid)
        if c and monto > 0:
            old_deuda = c.deuda or 0
            credito_obj = None
            if credito_id:
                credito_obj = db.session.get(Credito, credito_id)
                if not credito_obj or credito_obj.cliente_id != c.id or credito_obj.estado != "activo":
                    flash("El credito seleccionado no es valido para este cliente.", "warning")
                    return redirect(request.referrer or url_for("cobranzas"))
            else:
                credito_obj = obtener_credito_activo_cliente(c.id)

            limite_credito = credito_obj.saldo_actual if credito_obj else old_deuda
            monto_aplicado = min(monto, old_deuda, limite_credito)
            if monto_aplicado <= 0:
                flash("El cliente no tiene deuda pendiente por aplicar.", "warning")
                return redirect(request.referrer or url_for("cobranzas"))
            c.deuda = max(0, old_deuda - monto_aplicado)
            db.session.add(MovimientoCredito(
                cliente_id=c.id, 
                tipo='abono', 
                monto=monto_aplicado, 
                nota=nota, 
                usuario_id=session.get("user_id")
            ))
            if credito_obj:
                credito_obj.saldo_actual = max(0, (credito_obj.saldo_actual or 0) - monto_aplicado)
                numero_cuota = len(credito_obj.abonos) + 1
                db.session.add(AbonoCredito(
                    credito_id=credito_obj.id,
                    numero_cuota=numero_cuota,
                    monto=monto_aplicado,
                    saldo_posterior=credito_obj.saldo_actual,
                    usuario_id=session.get("user_id"),
                    nota=nota
                ))
                if credito_obj.saldo_actual <= 0:
                    credito_obj.estado = "Cancelado"
            db.session.flush()
            deuda_resultante = sincronizar_cartera_cliente(c.id)
            db.session.commit()
            registrar_auditoria("Abono", f"Cliente: {c.nombre} - Monto aplicado: {monto_aplicado} - Deuda anterior: {old_deuda}")
            if monto > monto_aplicado:
                flash(f"Abono aplicado por ${monto_aplicado:,.0f}. Se ignoró excedente de ${monto - monto_aplicado:,.0f}.", "warning")
            else:
                flash(f"Abono registrado correctamente. Saldo cartera: ${deuda_resultante:,.0f}", "success")
        else:
            flash("Error: Cliente no encontrado o monto inválido.", "warning")
    
    except Exception as e:
        db.session.rollback()
        flash(f"Error técnico al registrar abono: {e}", "danger")
    
    return redirect(request.referrer or url_for("cobranzas"))

# ==========================
# GESTIÓN DE CLIENTES
# ==========================
@app.route("/credito/formato/<int:credito_id>")
@cobrador_required
def formato_credito(credito_id):
    credito = Credito.query.get_or_404(credito_id)
    filas = construir_filas_ficha_credito(credito, max_filas=30)
    conf = Configuracion.query.first() or Configuracion()
    fecha = credito.fecha_inicio or datetime.now()
    obs = credito.observaciones or ""
    dia_pago_info = ""
    referencias_ficha = []
    for ln in obs.splitlines():
        texto = (ln or "").strip()
        if not texto:
            continue
        if texto.lower().startswith("dia de pago"):
            dia_pago_info = texto
        if texto.lower().startswith("referencia "):
            referencias_ficha.append(texto)
    return render_template(
        "credito_formato.html",
        credito=credito,
        filas_izq=filas[:15],
        filas_der=filas[15:30],
        config=conf,
        fecha=fecha,
        dia_pago_info=dia_pago_info,
        referencias_ficha=referencias_ficha[:2]
    )

@app.route("/api/intereses_credito")
@login_required
def api_intereses_credito():
    """Devuelve configuracion de credito (sin intereses) y opciones de dias de pago."""
    conf = Configuracion.query.first() or Configuracion()
    opciones = opciones_dia_pago_desde_config(conf)
    return jsonify({
        "Semanal": 0.0,
        "Quincenal": 0.0,
        "Mensual": 0.0,
        "aplicar": False,
        "cuota_fija": True,
        "dias_pago": opciones,
    })

@app.route("/api/alertas_cobro")
@login_required
def api_alertas_cobro():
    """Datos para alerta diaria al iniciar sesion."""
    actualizar_estados_cuotas()
    db.session.commit()
    hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    manana = hoy + timedelta(days=1)
    tres_dias = hoy + timedelta(days=3)
    siete_dias = hoy + timedelta(days=7)
    n_hoy = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= hoy,
        CuotaCredito.fecha_vencimiento < manana,
        CuotaCredito.estado.in_(["Pendiente", "Vence hoy"])
    ).count()
    total_hoy = db.session.query(func.sum(CuotaCredito.saldo_pendiente)).filter(
        CuotaCredito.fecha_vencimiento >= hoy,
        CuotaCredito.fecha_vencimiento < manana,
        CuotaCredito.estado.in_(["Pendiente", "Vence hoy"])
    ).scalar() or 0
    n_vencidas = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento < hoy,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).count()
    total_vencido = db.session.query(func.sum(CuotaCredito.saldo_pendiente)).filter(
        CuotaCredito.fecha_vencimiento < hoy,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).scalar() or 0
    n_proximas_3 = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= tres_dias,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).count()
    total_proximas_3 = db.session.query(func.sum(CuotaCredito.saldo_pendiente)).filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= tres_dias,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).scalar() or 0
    n_proximas_7 = CuotaCredito.query.filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= siete_dias,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).count()
    total_proximas_7 = db.session.query(func.sum(CuotaCredito.saldo_pendiente)).filter(
        CuotaCredito.fecha_vencimiento >= manana,
        CuotaCredito.fecha_vencimiento <= siete_dias,
        ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
    ).scalar() or 0

    proximas_detalle = (
        CuotaCredito.query
        .join(Credito, CuotaCredito.credito_id == Credito.id)
        .join(Cliente, Credito.cliente_id == Cliente.id)
        .filter(
            CuotaCredito.fecha_vencimiento >= manana,
            CuotaCredito.fecha_vencimiento <= siete_dias,
            ~CuotaCredito.estado.in_(["Pagada", "Cancelada"])
        )
        .order_by(CuotaCredito.fecha_vencimiento.asc())
        .limit(6)
        .all()
    )
    detalle = [
        {
            "cliente": (c.credito.cliente.nombre if c.credito and c.credito.cliente else "Cliente"),
            "credito": c.credito.codigo if c.credito else "---",
            "cuota": c.numero_cuota,
            "fecha": c.fecha_vencimiento.strftime("%Y-%m-%d"),
            "saldo": c.saldo_pendiente or 0,
        }
        for c in proximas_detalle
    ]
    return jsonify({
        "n_hoy": n_hoy, "total_hoy": total_hoy,
        "n_vencidas": n_vencidas, "total_vencido": total_vencido,
        "n_proximas_3": n_proximas_3, "total_proximas_3": total_proximas_3,
        "n_proximas_7": n_proximas_7, "total_proximas_7": total_proximas_7,
        "proximas_detalle": detalle,
    })

@app.route("/pagar_cuota/<int:cuota_id>", methods=["POST"])
@login_required
def pagar_cuota(cuota_id):
    """Registra pago o abono de una cuota individual, con amortización a futuras cuotas si el monto es mayor."""
    if session.get("rol") not in ["admin", "cobrador"]:
        return redirect(url_for("index"))
    try:
        cuota = db.session.get(CuotaCredito, cuota_id)
        if not cuota:
            flash("Cuota no encontrada.", "danger")
            return redirect(request.referrer or url_for("cobranzas"))
            
        monto_ingresado = parse_non_negative_int(request.form.get("monto_pago") or 0) or 0
        metodo = request.form.get("metodo_pago", "Efectivo")
        observacion = request.form.get("observacion", "")
        
        if monto_ingresado <= 0:
            flash("El monto debe ser mayor a cero.", "warning")
            return redirect(request.referrer or url_for("cobranzas"))

        credito = cuota.credito
        monto_a_distribuir = min(monto_ingresado, credito.saldo_actual)
        excedente = monto_ingresado - monto_a_distribuir

        # Obtener las cuotas pendientes desde la actual en adelante, o todas si pagan desde cualquier lado
        cuotas_pendientes = CuotaCredito.query.filter(
            CuotaCredito.credito_id == credito.id,
            CuotaCredito.saldo_pendiente > 0
        ).order_by(CuotaCredito.numero_cuota).all()

        monto_restante = monto_a_distribuir
        cuotas_afectadas = []
        saldo_credito_actual = credito.saldo_actual

        for c in cuotas_pendientes:
            if monto_restante <= 0:
                break
            
            pago_a_cuota = min(monto_restante, c.saldo_pendiente)
            c.valor_pagado = (c.valor_pagado or 0) + pago_a_cuota
            c.saldo_pendiente = max(0, c.saldo_pendiente - pago_a_cuota)
            c.metodo_pago = metodo
            c.observacion = observacion
            
            if c.saldo_pendiente <= 0:
                c.estado = "Pagada"
                c.fecha_pago = datetime.now()
            else:
                c.estado = "Abonada"
                
            monto_restante -= pago_a_cuota
            saldo_credito_actual -= pago_a_cuota
            cuotas_afectadas.append(str(c.numero_cuota))

            db.session.add(AbonoCredito(
                credito_id=credito.id,
                cuota_id=c.id,
                numero_cuota=c.numero_cuota,
                monto=pago_a_cuota,
                saldo_posterior=saldo_credito_actual,
                metodo_pago=metodo,
                usuario_id=session.get("user_id"),
                nota=observacion or f"Amortización cuota #{c.numero_cuota}"
            ))

        credito.saldo_actual = saldo_credito_actual
        if credito.saldo_actual <= 0:
            credito.estado = "Pagado"

        if monto_a_distribuir > 0:
            db.session.add(MovimientoCredito(
                cliente_id=credito.cliente_id,
                tipo='abono',
                monto=monto_a_distribuir,
                nota=f"Pago en cuota(s) #{', '.join(cuotas_afectadas)} - {credito.codigo}",
                usuario_id=session.get("user_id")
            ))
            
            sincronizar_cartera_cliente(credito.cliente_id)
            db.session.commit()
            registrar_auditoria("Pago Cuota", f"Cuotas: {', '.join(cuotas_afectadas)} - Credito {credito.codigo} - Monto: ${monto_a_distribuir:,.0f}")
            
            msg_exito = f"Pago de ${monto_a_distribuir:,.0f} registrado, aplicando a cuotas: {', '.join(cuotas_afectadas)}."
            if excedente > 0:
                msg_exito += f" Se ignoró un excedente de ${excedente:,.0f}."
            flash(msg_exito, "success")
        else:
            flash("El crédito ya no tiene saldo pendiente.", "info")

    except Exception as e:
        db.session.rollback()
        flash(f"Error al registrar pago: {e}", "danger")
    return redirect(request.referrer or url_for("cobranzas"))


@app.route("/clientes")
@admin_required
def clientes():
    sincronizar_cartera_global()
    db.session.commit()
    q = (request.args.get("q") or "").strip()
    vista = (request.args.get("vista") or "todos").strip().lower()
    if vista not in {"todos", "credito"}:
        vista = "todos"
    lista_q = Cliente.query
    if q:
        like = f"%{q}%"
        lista_q = lista_q.filter(
            or_(
                Cliente.nombre.ilike(like),
                Cliente.apellido.ilike(like),
                Cliente.telefono.ilike(like),
                Cliente.documento.ilike(like),
                Cliente.direccion.ilike(like),
                Cliente.email.ilike(like)
            )
        )
    lista = lista_q.order_by(Cliente.nombre.asc()).all()
    lista_credito = (
        lista_q
        .join(Credito, Credito.cliente_id == Cliente.id)
        .filter(
            Credito.saldo_actual > 0,
            Credito.estado.in_(["Activo", "En mora"])
        )
        .distinct()
        .order_by(Cliente.nombre.asc())
        .all()
    )
    clientes_mostrados = lista_credito if vista == "credito" else lista
    historial_clientes = MovimientoCredito.query.options(
        joinedload(MovimientoCredito.cliente)
    ).order_by(MovimientoCredito.fecha.desc()).limit(40).all()
    return render_template(
        "clientes.html",
        clientes=clientes_mostrados,
        historial_clientes=historial_clientes,
        search_q=q,
        vista=vista,
        total_clientes=len(lista),
        total_clientes_credito=len(lista_credito)
    )

@app.route("/clientes/<int:cliente_id>")
@admin_required
def cliente_historial(cliente_id):
    cliente = (
        Cliente.query
        .options(joinedload(Cliente.referencias))
        .filter(Cliente.id == cliente_id)
        .first_or_404()
    )
    sincronizar_cartera_cliente(cliente.id)
    db.session.commit()

    ventas = (
        Venta.query
        .options(joinedload(Venta.items).joinedload(DetalleVenta.producto))
        .filter(
            Venta.cliente_id == cliente.id,
            Venta.cerrado == True
        )
        .order_by(Venta.fecha_cierre.desc())
        .all()
    )

    creditos = (
        Credito.query
        .options(joinedload(Credito.cuotas))
        .filter(Credito.cliente_id == cliente.id)
        .order_by(Credito.fecha_inicio.desc())
        .all()
    )

    cuotas_pendientes = (
        CuotaCredito.query
        .options(joinedload(CuotaCredito.credito))
        .join(Credito, CuotaCredito.credito_id == Credito.id)
        .filter(
            Credito.cliente_id == cliente.id,
            CuotaCredito.saldo_pendiente > 0
        )
        .order_by(CuotaCredito.fecha_vencimiento.asc())
        .limit(30)
        .all()
    )

    abonos = (
        AbonoCredito.query
        .options(joinedload(AbonoCredito.credito), joinedload(AbonoCredito.usuario))
        .join(Credito, AbonoCredito.credito_id == Credito.id)
        .filter(Credito.cliente_id == cliente.id)
        .order_by(AbonoCredito.fecha.desc())
        .limit(100)
        .all()
    )

    movimientos = (
        MovimientoCredito.query
        .filter(MovimientoCredito.cliente_id == cliente.id)
        .order_by(MovimientoCredito.fecha.desc())
        .limit(100)
        .all()
    )

    referencias = sorted(list(cliente.referencias or []), key=lambda r: (r.orden or 9, -(r.id or 0)))
    # Fallback para datos antiguos donde referencias estaban solo en observaciones del crédito.
    if not referencias:
        for cr in creditos:
            refs_obs = extraer_referencias_desde_observaciones(cr.observaciones)
            if refs_obs:
                for ref in refs_obs:
                    referencias.append(type("RefFallback", (), {
                        "orden": ref.get("orden", 1),
                        "nombre": ref.get("nombre", ""),
                        "celular": ref.get("celular", ""),
                        "parentesco": ref.get("parentesco", ""),
                        "direccion": ref.get("direccion", ""),
                        "fecha_registro": cr.fecha_inicio,
                        "credito_id": cr.id,
                    })())
                break

    creditos_por_id = {cr.id: cr for cr in creditos}
    total_compras = sum(int(v.total or 0) for v in ventas)
    total_creditos = sum(int(c.total_financiado or 0) for c in creditos)
    total_abonos = sum(int(a.monto or 0) for a in abonos)
    saldo_creditos = sum(int(c.saldo_actual or 0) for c in creditos if int(c.saldo_actual or 0) > 0)
    total_pendiente = sum(int(c.saldo_pendiente or 0) for c in cuotas_pendientes)
    telefono_whatsapp = normalizar_telefono(cliente.telefono)

    return render_template(
        "cliente_detalle.html",
        cliente=cliente,
        ventas=ventas,
        creditos=creditos,
        creditos_por_id=creditos_por_id,
        cuotas_pendientes=cuotas_pendientes,
        abonos=abonos,
        movimientos=movimientos,
        referencias=referencias,
        nombre_completo=nombre_completo_cliente(cliente),
        total_compras=total_compras,
        total_creditos=total_creditos,
        total_abonos=total_abonos,
        saldo_creditos=saldo_creditos,
        total_pendiente=total_pendiente,
        telefono_whatsapp=telefono_whatsapp
    )

@app.route("/nuevo_cliente", methods=["POST"])
@login_required
def nuevo_cliente():
    tel = normalizar_telefono(request.form.get("telefono"))
    nom = (request.form.get("nombre") or "").strip()
    ape = (request.form.get("apellido") or "").strip()
    doc = normalizar_documento(request.form.get("documento"))
    email = (request.form.get("email") or "").strip()
    notas = (request.form.get("notas") or "").strip()
    dir = (request.form.get("direccion") or "").strip()
    
    if tel and nom and len(tel) >= 7:
        existe = Cliente.query.filter_by(telefono=tel).first()
        if existe:
            flash("El cliente ya existe con ese teléfono", "warning")
        else:
            if doc:
                existe_doc = Cliente.query.filter_by(documento=doc).first()
                if existe_doc:
                    flash("Ya existe un cliente con esa cédula/NIT.", "warning")
                    return redirect(request.referrer)
            c = Cliente(
                nombre=nom,
                apellido=ape or None,
                telefono=tel,
                documento=doc or None,
                direccion=dir or None,
                email=email or None,
                notas=notas or None
            )
            db.session.add(c)
            db.session.commit()
            flash("Cliente creado correctamente", "success")
            
    return redirect(request.referrer)

@app.route("/crear_credito_manual", methods=["POST"])
@admin_required
def crear_credito_manual():
    cliente_id = parse_non_negative_int(request.form.get("cliente_id_credito_manual"))
    return_to = (request.form.get("return_to") or "").strip()
    if not return_to.startswith("/"):
        return_to = ""
    cliente = db.session.get(Cliente, cliente_id) if cliente_id else None
    if not cliente:
        flash("Cliente no valido para crear credito.", "warning")
        return redirect(return_to or url_for("clientes"))
    try:
        credito_activo = obtener_credito_activo_cliente(cliente.id)
        estado_activo = (credito_activo.estado or "").lower() if credito_activo else ""
        if credito_activo and int(credito_activo.saldo_actual or 0) > 0 and estado_activo not in {"pagado", "cancelado"}:
            flash(f"El cliente ya tiene un credito activo ({credito_activo.codigo}).", "warning")
            return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))

        nombre_producto = (request.form.get("producto_credito") or request.form.get("descripcion_credito") or "").strip()
        saldo_pendiente = parse_non_negative_int(request.form.get("saldo_pendiente_credito") or request.form.get("monto_total_credito"))
        numero_cuotas = parse_non_negative_int(request.form.get("numero_cuotas_credito")) or 1
        numero_cuotas = max(1, min(numero_cuotas, 120))
        periodicidad_credito = (request.form.get("periodicidad_credito") or "Mensual").title()
        if periodicidad_credito not in ["Semanal", "Quincenal", "Mensual"]:
            periodicidad_credito = "Mensual"
        valor_cuota = parse_non_negative_int(request.form.get("valor_cuota_credito") or request.form.get("valor_cuota"))

        if not nombre_producto:
            flash("Debes ingresar el nombre del producto o concepto del credito.", "warning")
            return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))
        if saldo_pendiente is None or saldo_pendiente <= 0:
            flash("Debes ingresar un saldo pendiente valido para el credito.", "warning")
            return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))
        if valor_cuota is None or valor_cuota <= 0:
            flash("Debes ingresar un valor de cuota valido.", "warning")
            return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))

        cobertura_total = int(valor_cuota) * int(numero_cuotas)
        if cobertura_total < int(saldo_pendiente):
            flash("El valor de la cuota por el numero de cuotas no cubre el saldo pendiente.", "warning")
            return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))

        valor_ultima_cuota = int(saldo_pendiente)
        if numero_cuotas > 1:
            valor_ultima_cuota = int(saldo_pendiente) - (int(valor_cuota) * (int(numero_cuotas) - 1))
            if valor_ultima_cuota <= 0:
                flash("Con ese valor de cuota sobran cuotas. Ajusta el numero de cuotas o reduce el valor de la cuota.", "warning")
                return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))
            if valor_ultima_cuota > int(valor_cuota):
                flash("El valor de la cuota debe ser suficiente para cubrir el saldo dentro del numero de cuotas indicado.", "warning")
                return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))

        conf = Configuracion.query.first() or Configuracion()
        opts_map = opciones_dia_pago_desde_config(conf)
        pares_validos = []
        for op in opts_map.get(periodicidad_credito, []):
            try:
                pares_validos.append((int(str(op.get("value"))), str(op.get("label") or op.get("value"))))
            except Exception:
                pass
        if not pares_validos:
            pares_validos = [(1, "Dia 1")]
        valores_validos = {v for v, _ in pares_validos}
        etiqueta_map = {v: l for v, l in pares_validos}
        if periodicidad_credito == "Quincenal":
            dias = []
            for candidato in [parse_non_negative_int(request.form.get("dia_pago_credito_1")), parse_non_negative_int(request.form.get("dia_pago_credito_2"))]:
                if candidato in valores_validos and candidato not in dias:
                    dias.append(candidato)
            for valor_defecto, _ in pares_validos:
                if len(dias) >= 2:
                    break
                if valor_defecto not in dias:
                    dias.append(valor_defecto)
            dias = sorted(dias[:2])
            dia_pago_credito = dias
            dia_pago_texto = " y ".join(etiqueta_map.get(d, f"Dia {d}") for d in dias)
        else:
            dia_pago_credito = parse_non_negative_int(request.form.get("dia_pago_credito"))
            if dia_pago_credito not in valores_validos:
                dia_pago_credito = pares_validos[0][0]
            dia_pago_texto = etiqueta_map.get(dia_pago_credito, f"Dia {dia_pago_credito}")
        fecha_inicio_str = (request.form.get("fecha_inicio_credito", "") or "").strip()
        try:
            fecha_inicio_pago = datetime.strptime(fecha_inicio_str, "%Y-%m-%d")
        except Exception:
            fecha_inicio_pago = datetime.now()
        observaciones_extra = (request.form.get("observaciones_credito") or "").strip()

        venta_manual = Venta(
            fecha_creacion=fecha_inicio_pago,
            sede_id=session.get("sede_id"),
            cliente_id=cliente.id,
            vendedor_id=session.get("user_id"),
            estado="credito",
            estado_entrega="Pendiente",
            direccion_envio=cliente.direccion,
            cerrado=True,
            fecha_cierre=fecha_inicio_pago,
            metodo_pago="Credito",
            pago_efectivo=0,
            pago_tarjeta=0,
            pago_transferencia=0,
            total=int(saldo_pendiente),
            monto_recibido=0,
            cambio=0,
            notas=f"{nombre_producto} | Credito manual creado desde clientes"
        )
        db.session.add(venta_manual)
        db.session.flush()

        cliente.deuda = (cliente.deuda or 0) + int(saldo_pendiente)
        db.session.add(MovimientoCredito(
            cliente_id=cliente.id,
            tipo='cargo',
            monto=int(saldo_pendiente),
            nota=f"{nombre_producto} | Venta manual #{venta_manual.id} | Saldo ${saldo_pendiente:,.0f}",
            usuario_id=session.get("user_id")
        ))

        observaciones = [f"Dia de pago ({periodicidad_credito}): {dia_pago_texto}"]
        observaciones.append(f"Producto: {nombre_producto}")
        observaciones.append(f"Saldo pendiente: ${saldo_pendiente:,.0f}")
        observaciones.append(f"Numero de cuotas: {numero_cuotas}")
        observaciones.append(f"Valor de cuota: ${valor_cuota:,.0f}")
        if valor_ultima_cuota != int(valor_cuota):
            observaciones.append(f"Ultima cuota ajustada a ${valor_ultima_cuota:,.0f}")
        if observaciones_extra:
            observaciones.append(observaciones_extra)
        observaciones.append(f"Credito manual generado desde clientes para {nombre_completo_cliente(cliente)}")

        nuevo_credito = Credito(
            codigo=generar_codigo_credito(),
            fecha_inicio=fecha_inicio_pago,
            cliente_id=cliente.id,
            venta_id=venta_manual.id,
            periodicidad=periodicidad_credito,
            numero_cuotas=numero_cuotas,
            monto_total=int(saldo_pendiente),
            cuota_inicial=0,
            saldo_financiar=int(saldo_pendiente),
            porcentaje_interes=0.0,
            valor_interes=0,
            total_financiado=int(saldo_pendiente),
            valor_cuota=int(valor_cuota),
            saldo_actual=int(saldo_pendiente),
            estado="Activo",
            observaciones="\n".join(observaciones)[:300]
        )
        db.session.add(nuevo_credito)
        db.session.flush()
        generar_plan_pagos(nuevo_credito, fecha_inicio_pago, dia_pago_credito, 1, saldo_objetivo=int(saldo_pendiente))
        sincronizar_cartera_cliente(cliente.id)
        db.session.commit()
        try:
            registrar_auditoria("Credito Manual", f"Cliente {cliente.id} | Credito {nuevo_credito.codigo} | Producto {nombre_producto} | Saldo ${saldo_pendiente:,.0f}")
        except Exception:
            pass
        flash(f"Credito manual {nuevo_credito.codigo} creado correctamente para {nombre_completo_cliente(cliente)}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"No fue posible crear el credito manual: {e}", "danger")
    return redirect(return_to or url_for("cliente_historial", cliente_id=cliente.id))

@app.route("/eliminar_cliente/<int:cliente_id>", methods=["POST"])
@admin_required
def eliminar_cliente(cliente_id):
    c = db.session.get(Cliente, cliente_id)
    if not c:
        flash("Cliente no encontrado.", "warning")
        return redirect(url_for("clientes"))

    if c.deuda and c.deuda > 0:
        flash("Error: El cliente tiene deuda pendiente y no puede ser borrado.", "danger")
        return redirect(url_for("clientes"))

    try:
        creditos_cliente = Credito.query.filter_by(cliente_id=c.id).all()
        credito_ids = [cr.id for cr in creditos_cliente]

        if credito_ids:
            ReferenciaCliente.query.filter(
                ReferenciaCliente.credito_id.in_(credito_ids)
            ).delete(synchronize_session=False)
            AbonoCredito.query.filter(
                AbonoCredito.credito_id.in_(credito_ids)
            ).delete(synchronize_session=False)
            CuotaCredito.query.filter(
                CuotaCredito.credito_id.in_(credito_ids)
            ).delete(synchronize_session=False)
            Credito.query.filter(
                Credito.id.in_(credito_ids)
            ).delete(synchronize_session=False)

        Venta.query.filter_by(cliente_id=c.id).update({"cliente_id": None}, synchronize_session=False)
        ReferenciaCliente.query.filter_by(cliente_id=c.id).delete(synchronize_session=False)
        MovimientoCredito.query.filter_by(cliente_id=c.id).delete(synchronize_session=False)
        db.session.delete(c)
        db.session.commit()

        try:
            registrar_auditoria("Eliminar Cliente", f"Cliente {cliente_id} eliminado con limpieza de historial relacionado")
        except Exception:
            pass

        flash("Cliente eliminado correctamente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"No fue posible eliminar el cliente: {e}", "danger")

    return redirect(url_for("clientes"))
            

# ==========================
# HISTORIAL Y DEVOLUCIONES
# ==========================
@app.route("/ventas")
@admin_required
def historial_ventas():
    query = Venta.query.filter(Venta.cerrado == True, Venta.estado != 'Cotizacion')
    
    # Filtros
    v_id = request.args.get("venta_id")
    if v_id: query = query.filter(Venta.id == v_id)
    
    cliente_nom = request.args.get("cliente")
    if cliente_nom:
        query = query.join(Cliente).filter(Cliente.nombre.ilike(f"%{cliente_nom}%"))

    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.outerjoin(Cliente).filter(
            or_(
                Venta.notas.ilike(like),
                Venta.metodo_pago.ilike(like),
                Venta.estado.ilike(like),
                Cliente.nombre.ilike(like),
                Cliente.telefono.ilike(like)
            )
        )
        
    query = query.order_by(Venta.fecha_cierre.desc())
    ventas = query.limit(100).all()
    
    return render_template("ventas.html", ventas=ventas, search_q=q)

@app.route("/api/devolucion", methods=["POST"])
@admin_required
def api_devolucion():
    detalle_id = request.form.get("detalle_id")
    cant_a_devolver = parse_non_negative_int(request.form.get("cantidad", 0)) or 0
    motivo = request.form.get("motivo", "Devolución General")
    
    item = DetalleVenta.query.get_or_404(detalle_id)
    venta = item.venta
    
    # Validaciones
    disp_para_dev = item.cantidad - item.cantidad_devuelta
    if cant_a_devolver <= 0 or cant_a_devolver > disp_para_dev:
        flash("Cantidad de devolución inválida", "danger")
        return redirect(request.referrer)
    
    # 1. Actualizar DetalleVenta
    item.cantidad_devuelta += cant_a_devolver
    
    # 2. Incrementar Stock en Bodega de Dañados
    inv = InventarioSede.query.filter_by(producto_id=item.producto_id, sede_id=venta.sede_id).first()
    if not inv:
        inv = InventarioSede(producto_id=item.producto_id, sede_id=venta.sede_id, cantidad=0, cantidad_danado=0)
        db.session.add(inv)
    inv.cantidad_danado += cant_a_devolver
    
    # 3. Lógica Financiera (Reembolso Automático)
    valor_devuelto = cant_a_devolver * item.precio_unitario
    
    # Si hay deuda del cliente, restamos a la deuda primero
    if venta.cliente and venta.cliente.deuda > 0:
        a_restar_deuda = min(venta.cliente.deuda, valor_devuelto)
        venta.cliente.deuda -= a_restar_deuda
        db.session.add(MovimientoCredito(
            cliente_id=venta.cliente_id,
            tipo='abono',
            monto=a_restar_deuda,
            nota=f"Crédito por Devolución Item {item.producto.nombre} (Venta #{venta.id}) - {motivo}",
            usuario_id=session.get("user_id")
        ))
        valor_devuelto -= a_restar_deuda
    
    # Si queda saldo (porque ya pagó o superó la deuda), generamos un Gasto automático
    if valor_devuelto > 0:
        db.session.add(Gasto(
            descripcion=f"REEMBOLSO Devolución: {item.producto.nombre} (Venta #{venta.id}) - {motivo}",
            monto=valor_devuelto,
            tipo_gasto='devolucion',
            sede_id=venta.sede_id,
            usuario_id=session.get("user_id")
        ))
        
    db.session.commit()
    flash(f"Devolución procesada: {cant_a_devolver} {item.producto.nombre} a Bodega de Dañados.", "success")
    return redirect(request.referrer)


# ==========================
# SECCIÓN ADMIN / CRUD
# ==========================
@app.route("/admin", methods=["GET","POST"])
@inventario_required
def admin():
    rol_actual = session.get("rol")
    solo_inventario = rol_actual == "bodega"
    solo_consulta = rol_actual == "vendedor"
    usuario_actual = obtener_usuario_actual()
    sedes_visibles = sedes_visibles_para_usuario(usuario_actual)
    if not sedes_visibles:
        flash("No hay una sede activa disponible para este usuario.", "warning")
        return redirect(url_for("index"))

    if rol_actual == "admin":
        sede_actual = obtener_sede_activa(session.get("sede_id")) or sedes_visibles[0]
    else:
        sede_actual = sedes_visibles[0]
        session["sede_id"] = sede_actual.id

    if request.method=="POST": 
        try:
            t=request.form.get("tipo")
            if solo_consulta:
                flash("Tu usuario solo puede consultar el inventario de la sede asignada.", "warning")
                return redirect(url_for("admin"))
            if solo_inventario and t not in {"update_imagen"}:
                flash("Tu rol de bodega solo puede ajustar existencias y actualizar imagenes de producto.", "warning")
                return redirect(url_for("admin"))

            if t=="producto": 
                cat_id = request.form.get("categoria_id")
                nombre_prod = (request.form.get("nombre") or "").strip()
                precio_prod = parse_non_negative_int(request.form.get("precio"))
                if not nombre_prod or precio_prod is None or precio_prod <= 0:
                    flash("Nombre y precio del producto son obligatorios.", "warning")
                    return redirect(request.referrer or url_for("admin"))
                imagen_filename = None
                imagen_file = request.files.get("imagen")
                if imagen_file and imagen_file.filename:
                    filename = secure_filename(imagen_file.filename)
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    imagen_file.save(save_path)
                    imagen_filename = filename

                nuevo_p = Producto(
                    nombre=nombre_prod, 
                    precio=precio_prod, 
                    categoria_id=cat_id,
                    descripcion=request.form.get("descripcion", ""),
                    imagen_url=imagen_filename
                )
                db.session.add(nuevo_p)
                db.session.flush()
                
                sedes_all = Sede.query.all()
                for s in sedes_all:
                    db.session.add(InventarioSede(producto_id=nuevo_p.id, sede_id=s.id, cantidad=0))
                
                db.session.commit()
                registrar_auditoria("Producto", f"Creado producto: {nuevo_p.nombre} - Precio: {nuevo_p.precio}")

            elif t=="update_precio": 
                p = db.session.get(Producto, request.form.get("producto_id"))
                if p:
                    nuevo_precio = parse_non_negative_int(request.form.get("precio"))
                    if nuevo_precio is None or nuevo_precio <= 0:
                        flash("Precio invalido para el producto.", "warning")
                        return redirect(request.referrer or url_for("admin"))
                    old_price = p.precio
                    p.precio = nuevo_precio
                    db.session.commit()
                    registrar_auditoria("Precio", f"Producto: {p.nombre} - Precio anterior: {old_price} - Nuevo: {p.precio}")

            elif t=="update_imagen":
                p = db.session.get(Producto, request.form.get("producto_id"))
                imagen_file = request.files.get("imagen")
                if not p:
                    flash("Producto no encontrado para actualizar imagen.", "warning")
                    return redirect(request.referrer or url_for("admin"))
                if not imagen_file or not imagen_file.filename:
                    flash("Debes seleccionar una imagen valida.", "warning")
                    return redirect(request.referrer or url_for("admin"))

                nombre_seguro = secure_filename(imagen_file.filename)
                _, ext = os.path.splitext(nombre_seguro)
                ext = (ext or "").lower()
                extensiones_permitidas = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
                if ext not in extensiones_permitidas:
                    flash("Formato no permitido. Usa PNG, JPG, WEBP, GIF o BMP.", "warning")
                    return redirect(request.referrer or url_for("admin"))

                nombre_final = f"prod_{p.id}_{int(datetime.now().timestamp())}{ext}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], nombre_final)
                imagen_file.save(save_path)
                p.imagen_url = nombre_final
                db.session.commit()
                registrar_auditoria("Imagen", f"Actualizada imagen de producto: {p.nombre}")
                flash("Imagen actualizada correctamente.", "success")

            elif t=="toggle_producto": 
                p = db.session.get(Producto, request.form.get("producto_id"))
                if p:
                    p.activo = not p.activo
                    db.session.commit()
                    registrar_auditoria("Estado", f"Producto: {p.nombre} - {'Activado' if p.activo else 'Desactivado'}")

        except Exception as e:
            db.session.rollback()
            flash(f"Error en operacion administrativa: {e}", "danger")
    
    cat_filtro = request.args.get("categoria_id")
    search_q = (request.args.get("q") or "").strip()
    query_prod = Producto.query.filter_by(is_deleted=False)

    if cat_filtro and cat_filtro != 'Todas' and cat_filtro.isdigit():
        query_prod = query_prod.filter_by(categoria_id=int(cat_filtro))
        cat_filtro = int(cat_filtro)
    else:
        cat_filtro = 'Todas'

    if search_q:
        like = f"%{search_q}%"
        query_prod = query_prod.outerjoin(Categoria, Producto.categoria_id == Categoria.id).filter(
            or_(
                Producto.nombre.ilike(like),
                Producto.descripcion.ilike(like),
                Categoria.nombre.ilike(like)
            )
        )

    sedes_panel = Sede.query.filter_by(activa=True).order_by(Sede.nombre.asc()).all() if rol_actual in {"admin", "vendedor"} else [sede_actual]

    return render_template("admin.html", 
                           productos=query_prod.all(), 
                           categorias=Categoria.query.all(), 
                           sedes=sedes_panel,
                           sede_actual=sede_actual,
                           cat_filtro=cat_filtro,
                           solo_inventario=solo_inventario,
                           solo_consulta=solo_consulta,
                           search_q=search_q)

@app.route("/seleccionar_sede/<int:sede_id>")
@login_required
def seleccionar_sede(sede_id):
    s = obtener_sede_activa(sede_id)
    if not s:
        abort(404)
    usuario_actual = obtener_usuario_actual()
    if usuario_actual and usuario_actual.rol != "admin":
        if not usuario_puede_operar_sede(s.id, usuario_actual):
            if usuario_actual.sede_id:
                session["sede_id"] = usuario_actual.sede_id
            flash("Solo puedes consultar la sede asignada a tu usuario.", "warning")
            return redirect(request.referrer or url_for('index'))
        session["sede_id"] = usuario_actual.sede_id
        return redirect(request.referrer or url_for('index'))
    sede_actual = session.get("sede_id")
    session["sede_id"] = s.id
    if sede_actual != s.id:
        flash(f"Cambiado a sucursal: {s.nombre}", "info")
    return redirect(request.referrer or url_for('index'))

@app.route("/api/pos/stock/<int:prod_id>/<int:sede_id>")
@login_required
def api_stock_realtime(prod_id, sede_id):
    if not usuario_puede_operar_sede(sede_id):
        return jsonify({"error": "Acceso denegado para esta sede."}), 403
    inv = InventarioSede.query.filter_by(producto_id=prod_id, sede_id=sede_id).first()
    stock_local = inv.cantidad if inv else 0
    danado_local = inv.cantidad_danado if inv else 0
    
    # Otros en otras sedes
    otros = db.session.query(func.sum(InventarioSede.cantidad)).filter(
        InventarioSede.producto_id == prod_id,
        InventarioSede.sede_id != sede_id
    ).scalar() or 0
    
    return jsonify({
        "stock_local": stock_local,
        "stock_danado": danado_local,
        "stock_global": stock_local + otros,
        "otros_sedes": otros
    })

@app.route("/api/stock/actualizar", methods=["POST"])
@inventario_required
def actualizar_stock():
    try:
        if session.get("rol") == "vendedor":
            raise PermissionError("Tu rol solo puede consultar inventario.")
        prod_id = parse_non_negative_int(request.form.get("producto_id"))
        sede_id = parse_non_negative_int(request.form.get("sede_id"))
        if sede_id is not None and not usuario_puede_operar_sede(sede_id):
            raise PermissionError("Solo puedes ajustar inventario de tu sede asignada.")
        if prod_id is None or sede_id is None:
            raise ValueError("Producto o sede no validos.")
        cant = parse_non_negative_int(request.form.get("cantidad"))
        cant_danado = parse_non_negative_int(request.form.get("cantidad_danado"))
        if cant is None and cant_danado is None:
            raise ValueError("Debes enviar stock disponible y/o danado.")
        
        app.logger.info(f"Actualizando Stock: Prod({prod_id}) Sede({sede_id}) Cant({cant}) Danado({cant_danado})")

        inv = InventarioSede.query.filter_by(producto_id=prod_id, sede_id=sede_id).first()
        if not inv:
            inv = InventarioSede(producto_id=prod_id, sede_id=sede_id, cantidad=0, cantidad_danado=0)
            db.session.add(inv)
            
        if cant is not None:
            old_stock = inv.cantidad or 0
            inv.cantidad = cant
            db.session.add(MovimientoInventario(
                producto_id=prod_id,
                sede_id=sede_id,
                tipo='AJUSTE',
                cantidad=cant - old_stock,
                stock_anterior=old_stock,
                stock_nuevo=cant,
                usuario_id=session.get("user_id"),
                referencia="Ajuste manual (Panel Admin) - Disponible"
            ))
        if cant_danado is not None:
            old_danado = inv.cantidad_danado or 0
            inv.cantidad_danado = cant_danado
            db.session.add(MovimientoInventario(
                producto_id=prod_id,
                sede_id=sede_id,
                tipo='AJUSTE_DANADO',
                cantidad=cant_danado - old_danado,
                stock_anterior=old_danado,
                stock_nuevo=cant_danado,
                usuario_id=session.get("user_id"),
                referencia="Ajuste manual (Panel Admin) - Danado"
            ))
        db.session.commit()
        
        flash("Stock actualizado correctamente.", "success")
        
        # Si es peticion AJAX, respondemos JSON, si no, redireccionamos
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({
                "status": "ok",
                "new_stock": inv.cantidad,
                "new_stock_danado": inv.cantidad_danado
            })
            
        return redirect(request.referrer or url_for('admin'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en actualizar_stock: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({"status": "error", "message": str(e)}), 500
        flash(f"Error al actualizar stock: {e}", "danger")
        return redirect(request.referrer or url_for('admin'))

@app.route("/api/stock/actualizar_masivo", methods=["POST"])
@inventario_required
def actualizar_stock_masivo():
    try:
        if session.get("rol") == "vendedor":
            raise PermissionError("Tu rol solo puede consultar inventario.")
        prod_id = parse_non_negative_int(request.form.get("producto_id"))
        if prod_id is None:
            raise ValueError("Producto no valido.")

        sede_ids_raw = request.form.getlist("sede_id[]") or request.form.getlist("sede_id")
        cantidades_raw = request.form.getlist("cantidad[]") or request.form.getlist("cantidad")
        danados_raw = request.form.getlist("cantidad_danado[]") or request.form.getlist("cantidad_danado")

        if not sede_ids_raw:
            raise ValueError("No se recibieron sedes para actualizar.")
        if len(sede_ids_raw) != len(cantidades_raw) or len(sede_ids_raw) != len(danados_raw):
            raise ValueError("Datos incompletos para actualizar todas las sedes.")

        cambios = 0
        for idx, sede_raw in enumerate(sede_ids_raw):
            sede_id = parse_non_negative_int(sede_raw)
            if sede_id is not None and not usuario_puede_operar_sede(sede_id):
                raise PermissionError("Solo puedes ajustar inventario de tu sede asignada.")
            cant = parse_non_negative_int(cantidades_raw[idx])
            cant_danado = parse_non_negative_int(danados_raw[idx])
            if sede_id is None or cant is None or cant_danado is None:
                raise ValueError(f"Valores invalidos en la sede #{idx + 1}.")

            inv = InventarioSede.query.filter_by(producto_id=prod_id, sede_id=sede_id).first()
            if not inv:
                inv = InventarioSede(producto_id=prod_id, sede_id=sede_id, cantidad=0, cantidad_danado=0)
                db.session.add(inv)

            old_stock = inv.cantidad or 0
            old_danado = inv.cantidad_danado or 0

            inv.cantidad = cant
            inv.cantidad_danado = cant_danado

            if old_stock != cant:
                cambios += 1
                db.session.add(MovimientoInventario(
                    producto_id=prod_id,
                    sede_id=sede_id,
                    tipo='AJUSTE',
                    cantidad=cant - old_stock,
                    stock_anterior=old_stock,
                    stock_nuevo=cant,
                    usuario_id=session.get("user_id"),
                    referencia="Ajuste masivo (Panel Admin) - Disponible"
                ))

            if old_danado != cant_danado:
                cambios += 1
                db.session.add(MovimientoInventario(
                    producto_id=prod_id,
                    sede_id=sede_id,
                    tipo='AJUSTE_DANADO',
                    cantidad=cant_danado - old_danado,
                    stock_anterior=old_danado,
                    stock_nuevo=cant_danado,
                    usuario_id=session.get("user_id"),
                    referencia="Ajuste masivo (Panel Admin) - Danado"
                ))

        db.session.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({
                "status": "ok",
                "sedes_actualizadas": len(sede_ids_raw),
                "cambios_registrados": cambios
            })

        flash("Inventario actualizado correctamente para la sede seleccionada.", "success")
        return redirect(request.referrer or url_for('admin'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en actualizar_stock_masivo: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({"status": "error", "message": str(e)}), 500
        flash(f"Error al actualizar stock masivo: {e}", "danger")
        return redirect(request.referrer or url_for('admin'))

@app.route("/admin/eliminar_producto/<int:prod_id>", methods=["POST"])
@admin_required
def eliminar_producto_admin(prod_id):
    p = Producto.query.get(prod_id)
    if p:
        p.is_deleted = True
        db.session.commit()
    return redirect(url_for("admin"))

# ==========================
# CATEGORÍAS
# ==========================
@app.route("/admin/categorias", methods=["POST"])
@admin_required
def admin_categorias():
    nombre = (request.form.get("nombre") or "").strip()
    if not nombre:
        flash("Debes escribir un nombre de categoria.", "warning")
        return redirect(url_for("admin"))
    ya_existe = Categoria.query.filter(func.lower(Categoria.nombre) == nombre.lower()).first()
    if ya_existe:
        flash("La categoria ya existe.", "warning")
        return redirect(url_for("admin"))
    db.session.add(Categoria(nombre=nombre))
    db.session.commit()
    return redirect(url_for("admin"))

@app.route("/admin/eliminar_categoria/<int:id>", methods=["POST"])
@admin_required
def eliminar_categoria(id):
    c = Categoria.query.get(id)
    if c:
        for p in c.productos:
            p.is_deleted = True
        db.session.delete(c)
        db.session.commit()
    return redirect(url_for("admin"))

@app.route("/sedes", methods=["GET", "POST"])
@admin_required
def sedes():
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        if not nombre:
            flash("El nombre de la sede es obligatorio.", "warning")
            return redirect(request.referrer or url_for("sedes"))
        db.session.add(Sede(
            nombre=nombre,
            direccion=request.form.get("direccion"),
            telefono=request.form.get("telefono")
        ))
        db.session.commit()
        flash("Sede creada", "success")
    return render_template("sedes.html", sedes=Sede.query.all())

@app.route("/usuarios", methods=["GET","POST"])
@admin_required
def usuarios():
    if request.method=="POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        rol = request.form.get("rol")
        sede_id = request.form.get("sede_id") or None
        roles_validos = {"admin", "vendedor", "cobrador", "bodega"}

        if not username or len(password) < 4 or rol not in roles_validos:
            flash("Datos de usuario invalidos. Verifica nombre, clave y rol.", "warning")
            return redirect(url_for("usuarios"))
        if rol == "vendedor" and not sede_id:
            flash("Los vendedores deben tener una sede asignada.", "warning")
            return redirect(url_for("usuarios"))

        db.session.add(Usuario(
            username=username,
            password_hash=generate_password_hash(password),
            rol=rol,
            sede_id=sede_id
        ))
        try:
            db.session.commit()
            flash("Usuario creado correctamente.", "success")
        except IntegrityError:
            db.session.rollback()
            flash("El nombre de usuario ya existe.", "warning")
    return render_template("usuarios.html", usuarios=Usuario.query.all(), sedes=Sede.query.filter_by(activa=True).all())

@app.route("/eliminar_usuario/<int:user_id>", methods=["POST"])
@admin_required
def eliminar_usuario(user_id):
    if user_id!=session["user_id"]:
        u = Usuario.query.get(user_id)
        if u:
            db.session.delete(u)
            db.session.commit()
    return redirect(url_for("usuarios"))

@app.route("/usuarios/<int:user_id>/cambiar_clave", methods=["POST"])
@admin_required
def cambiar_clave_usuario(user_id):
    u = Usuario.query.get_or_404(user_id)
    nueva_clave = request.form.get("nueva_clave") or ""
    confirmar_clave = request.form.get("confirmar_clave") or ""

    if len(nueva_clave) < 4:
        flash("La nueva clave debe tener minimo 4 caracteres.", "warning")
        return redirect(url_for("usuarios"))

    if nueva_clave != confirmar_clave:
        flash("Las claves no coinciden.", "warning")
        return redirect(url_for("usuarios"))

    u.password_hash = generate_password_hash(nueva_clave)
    db.session.commit()
    flash(f"Clave actualizada para el usuario {u.username}.", "success")
    return redirect(url_for("usuarios"))

# ==========================
# CAJA Y REPORTES
# ==========================
@app.route("/caja", methods=["GET", "POST"])
@admin_required
def caja():
    if request.method == "POST":
        if "nuevo_gasto" in request.form:
            monto = parse_non_negative_int(request.form.get("monto"))
            if monto is None or monto <= 0:
                flash("El monto del gasto debe ser mayor a cero.", "warning")
                return redirect(request.referrer or url_for("caja"))
            db.session.add(Gasto(
                descripcion=request.form.get("descripcion"),
                monto=monto,
                tipo_gasto=request.form.get("tipo_gasto", "operativo"),
                sede_id=request.form.get("sede_id") or None,
                usuario_id=session["user_id"]
            ))
            db.session.commit()
            flash("Gasto registrado", "success")
        elif "eliminar_gasto" in request.form:
            g = Gasto.query.get(request.form.get("gasto_id"))
            if g: db.session.delete(g); db.session.commit()
    
    conf = Configuracion.query.first() or Configuracion(base_caja=0)
    if request.args.get("actualizar_base"):
        try: 
            conf.base_caja = int(request.args.get("base_caja"))
            db.session.add(conf) # Ensure it's in session if it was newly created
            db.session.commit()
        except: pass

    sede_filtro = parse_non_negative_int(request.args.get("sede_id"))

    f_str=request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    st, en = datetime.strptime(f_str,'%Y-%m-%d').replace(hour=0,minute=0), datetime.strptime(f_str,'%Y-%m-%d').replace(hour=23,minute=59)
    
    query_ventas = Venta.query.filter(
        Venta.cerrado==True,
        Venta.estado != 'Cotizacion',
        Venta.fecha_cierre>=st,
        Venta.fecha_cierre<=en
    )
    query_gastos = Gasto.query.filter(Gasto.fecha>=st, Gasto.fecha<=en)
    
    # Nuevos abonos del día (para la caja)
    query_abonos = AbonoCredito.query.filter(AbonoCredito.fecha>=st, AbonoCredito.fecha<=en)

    if sede_filtro is not None:
        query_ventas = query_ventas.filter(Venta.sede_id == sede_filtro)
        query_gastos = query_gastos.filter(Gasto.sede_id == sede_filtro)
        query_abonos = query_abonos.join(Credito).join(Venta, Credito.venta_id == Venta.id).filter(Venta.sede_id == sede_filtro)

    ventas = query_ventas.all()
    gastos = query_gastos.all()
    abonos = query_abonos.all()
    sedes_activas = Sede.query.filter_by(activa=True).all()
    sedes_map = {s.id: s.nombre for s in sedes_activas}

    te = 0
    td = 0
    movimientos_caja = []

    # Sumar pagos de ventas directas y cuotas iniciales de creditos
    for v in ventas:
        monto_movimiento_venta = 0
        metodo_movimiento_venta = v.metodo_pago or "---"
        detalle_movimiento_venta = f"Venta #{v.id}"

        if v.metodo_pago == "Credito":
            # La cuota inicial se asume en efectivo por defecto a menos que agreguemos un selector luego,
            # pero tipicamente ingresa en caja fisica.
            credito = Credito.query.filter_by(venta_id=v.id).first()
            cuota_inicial = int(credito.cuota_inicial or 0) if credito else 0
            if cuota_inicial > 0:
                te += cuota_inicial
                monto_movimiento_venta = cuota_inicial
                metodo_movimiento_venta = "Credito / Cuota inicial"
                detalle_movimiento_venta = f"Venta #{v.id} - Cuota inicial"
        else:
            efectivo, tarjeta, transferencia = desglose_pago_venta(v)
            te += efectivo
            td += (tarjeta + transferencia)
            monto_movimiento_venta = int(efectivo + tarjeta + transferencia)

        if monto_movimiento_venta > 0:
            movimientos_caja.append({
                "fecha": v.fecha_cierre or v.fecha_creacion,
                "tipo": "Venta",
                "detalle": detalle_movimiento_venta,
                "sede": v.sede.nombre if v.sede else "Sin sede",
                "metodo": metodo_movimiento_venta,
                "responsable": v.vendedor.username if v.vendedor else "---",
                "monto": monto_movimiento_venta,
                "clase_monto": "text-success",
                "ticket_url": url_for("imprimir_ticket", venta_id=v.id)
            })

    # Sumar pagos de cuotas realizados en el modulo de cobranzas
    for a in abonos:
        if a.metodo_pago and a.metodo_pago.lower() in ['tarjeta', 'transferencia', 'digital']:
            td += a.monto
        else:
            te += a.monto

        credito = a.credito
        venta_credito = credito.venta if credito else None
        cliente_credito = credito.cliente if credito else None
        detalle_abono = f"Abono {credito.codigo}" if credito else f"Abono #{a.id}"
        if cliente_credito:
            detalle_abono += f" - {nombre_completo_cliente(cliente_credito)}"
        movimientos_caja.append({
            "fecha": a.fecha,
            "tipo": "Abono",
            "detalle": detalle_abono,
            "sede": venta_credito.sede.nombre if venta_credito and venta_credito.sede else "Sin sede",
            "metodo": a.metodo_pago or "Efectivo",
            "responsable": a.usuario.username if a.usuario else "---",
            "monto": int(a.monto or 0),
            "clase_monto": "text-primary",
            "ticket_url": ""
        })

    for g in gastos:
        movimientos_caja.append({
            "fecha": g.fecha,
            "tipo": "Gasto",
            "detalle": g.descripcion or f"Gasto #{g.id}",
            "sede": sedes_map.get(g.sede_id, "General"),
            "metodo": "Salida de efectivo",
            "responsable": g.usuario.username if g.usuario else "---",
            "monto": int(g.monto or 0),
            "clase_monto": "text-danger",
            "ticket_url": ""
        })

    movimientos_caja.sort(key=lambda mov: mov["fecha"] or datetime.min, reverse=True)

    tg = sum(g.monto for g in gastos)
    
    return render_template("caja.html", ventas=ventas, gastos=gastos,
                           total_efectivo=te, total_digital=td, total_gastos=tg,
                           base_caja=conf.base_caja,
                           dinero_en_caja=(te + conf.base_caja - tg),
                           neto=te+td-tg, fecha=f_str, total_dia=te+td,
                           movimientos_caja=movimientos_caja,
                           sedes=sedes_activas,
                           sede_actual=str(sede_filtro) if sede_filtro is not None else "")

@app.route("/reportes")
@admin_required
def reportes():
    # Fechas por defecto: Mes actual
    fi_str = request.args.get('fecha_inicio', datetime.now().replace(day=1).strftime('%Y-%m-%d'))
    ff_str = request.args.get('fecha_fin', datetime.now().strftime('%Y-%m-%d'))
    sede_filtro = parse_non_negative_int(request.args.get('sede_id'))
    
    st = datetime.strptime(fi_str, '%Y-%m-%d').replace(hour=0,minute=0)
    en = datetime.strptime(ff_str, '%Y-%m-%d').replace(hour=23,minute=59)

    # Consulta de Ventas
    query_ventas = Venta.query.filter(
        Venta.cerrado==True,
        Venta.estado != 'Cotizacion',
        Venta.fecha_cierre>=st,
        Venta.fecha_cierre<=en
    ).options(joinedload(Venta.items).joinedload(DetalleVenta.producto))
    
    # Consulta de Gastos
    query_gastos = Gasto.query.filter(Gasto.fecha>=st, Gasto.fecha<=en)

    if sede_filtro is not None:
        query_ventas = query_ventas.filter(Venta.sede_id == sede_filtro)
        query_gastos = query_gastos.filter(Gasto.sede_id == sede_filtro)

    ventas = query_ventas.all()
    gastos = query_gastos.all()

    # Métricas Básicas
    total_ventas = sum(v.total for v in ventas)
    total_pedidos = len(ventas)
    total_gastos = sum(g.monto for g in gastos)
    utilidad_estimada = total_ventas - total_gastos
    ticket_promedio = (total_ventas / total_pedidos) if total_pedidos > 0 else 0

    # Cartera y Stock (Globales o por Sede)
    if sede_filtro is not None:
        cartera_total = db.session.query(func.sum(Venta.total - Venta.monto_recibido)).filter(
            Venta.sede_id == sede_filtro,
            Venta.cerrado == True,
            Venta.estado != 'Cotizacion'
        ).scalar() or 0
        total_danados = db.session.query(func.sum(InventarioSede.cantidad_danado)).filter(InventarioSede.sede_id == sede_filtro).scalar() or 0
        stock_critico = InventarioSede.query.filter(InventarioSede.sede_id == sede_filtro, InventarioSede.cantidad < 3).limit(10).all()
    else:
        cartera_total = db.session.query(func.sum(Cliente.deuda)).scalar() or 0
        total_danados = db.session.query(func.sum(InventarioSede.cantidad_danado)).scalar() or 0
        stock_critico = InventarioSede.query.filter(InventarioSede.cantidad < 3).limit(10).all()

    # Agrupaciones para gráficos
    metodos = {}
    v_por_vendedor = {}
    v_por_fecha = {} # Para el gráfico de tendencia

    for v in ventas:
        m = v.metodo_pago or "Desconocido"
        metodos[m] = metodos.get(m, 0) + v.total
        
        v_nom = v.vendedor.username if v.vendedor else "Sin Asignar"
        v_por_vendedor[v_nom] = v_por_vendedor.get(v_nom, 0) + v.total
        
        f_key = v.fecha_cierre.strftime('%Y-%m-%d')
        v_por_fecha[f_key] = v_por_fecha.get(f_key, 0) + v.total

    # Top Productos
    prod_count = {}
    for v in ventas:
        for d in v.items:
             n = d.producto.nombre if d.producto else "Desconocido"
             prod_count[n] = prod_count.get(n, {'qty':0, 'total':0})
             prod_count[n]['qty'] += d.cantidad
             prod_count[n]['total'] += (d.precio_unitario * d.cantidad)
    
    top_productos = sorted([(k, val['qty'], val['total']) for k,val in prod_count.items()], key=lambda x: x[1], reverse=True)[:5]

    # Métricas específicas de Créditos
    query_creditos = Credito.query.filter(Credito.fecha_inicio >= st, Credito.fecha_inicio <= en)
    if sede_filtro is not None:
        query_creditos = query_creditos.join(Venta, Credito.venta_id == Venta.id).filter(Venta.sede_id == sede_filtro)
    
    creditos_filtrados = query_creditos.all()
    intereses_generados = sum((c.valor_interes or 0) for c in creditos_filtrados)
    
    estado_creditos = {}
    for c in creditos_filtrados:
        e = c.estado or "Activo"
        estado_creditos[e] = estado_creditos.get(e, 0) + 1

    return render_template("reportes.html", 
                           fecha_ini=fi_str, fecha_fin=ff_str,
                           total_ventas=total_ventas, 
                           total_pedidos=total_pedidos, 
                           total_gastos=total_gastos,
                           utilidad=utilidad_estimada,
                           cartera=cartera_total,
                           danados=total_danados,
                           stock_alerta=stock_critico,
                           ticket_promedio=ticket_promedio,
                           metodos_pago=metodos,
                           ventas_vendedor=v_por_vendedor,
                           ventas_fecha=v_por_fecha,
                           top_productos=top_productos,
                           intereses_generados=intereses_generados,
                           estado_creditos=estado_creditos,
                           sedes=Sede.query.filter_by(activa=True).all(),
                           sede_actual=str(sede_filtro) if sede_filtro is not None else "")


@app.route("/admin/configuracion", methods=["GET","POST"])
@admin_required
def admin_configuracion():
    c = Configuracion.query.first() or Configuracion()
    
    if request.method=="POST": 
        if not c.id:
            db.session.add(c)
        c.nombre_empresa=request.form.get("nombre_empresa")
        c.nit=request.form.get("nit")
        c.direccion=request.form.get("direccion")
        c.telefono=request.form.get("telefono")
        c.mensaje_ticket=request.form.get("mensaje_ticket")

        # Credito a cuota fija (sin intereses)
        c.interes_semanal = 0.0
        c.interes_quincenal = 0.0
        c.interes_mensual = 0.0
        c.aplicar_interes_credito = False
        try: c.mora_porcentaje = float(request.form.get("mora_porcentaje") or 2.0)
        except: pass
        try: c.dias_gracia = int(request.form.get("dias_gracia") or 0)
        except: pass

        # Opciones editables de dias de pago (formato por linea: valor|etiqueta)
        defs = opciones_dia_pago_default()
        sem_txt = request.form.get("dias_pago_semanal_conf", "")
        qui_txt = request.form.get("dias_pago_quincenal_conf", "")
        men_txt = request.form.get("dias_pago_mensual_conf", "")
        sem_opts = parsear_opciones_desde_texto("Semanal", sem_txt) or defs["Semanal"]
        qui_opts = parsear_opciones_desde_texto("Quincenal", qui_txt) or defs["Quincenal"]
        men_opts = parsear_opciones_desde_texto("Mensual", men_txt) or defs["Mensual"]
        c.dias_pago_semanal = serializar_opciones_dia_pago(sem_opts)
        c.dias_pago_quincenal = serializar_opciones_dia_pago(qui_opts)
        c.dias_pago_mensual = serializar_opciones_dia_pago(men_opts)
        db.session.commit()
        flash("Configuracion actualizada correctamente.", "success")

    opts_cfg = opciones_dia_pago_desde_config(c)
    return render_template(
        "configuracion.html",
        conf=c,
        dias_pago_semanal_txt=opciones_dia_pago_a_texto(opts_cfg["Semanal"]),
        dias_pago_quincenal_txt=opciones_dia_pago_a_texto(opts_cfg["Quincenal"]),
        dias_pago_mensual_txt=opciones_dia_pago_a_texto(opts_cfg["Mensual"])
    )



# ==========================
# GENERACIÓN DE PDF
# ==========================
def safe_text(text):
    """Convierte texto a latin-1 seguro para FPDF."""
    if not text:
        return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def draw_muebleria_logo_pdf(pdf, x, y, size=18):
    """Renderiza el logo principal en PDF y deja un respaldo vectorial si falla la imagen."""
    if os.path.exists(BRAND_LOGO_PATH):
        try:
            pdf.image(BRAND_LOGO_PATH, x=x, y=y, w=size, h=size)
            return
        except Exception:
            pass

    segmentos = [
        (45, 60, 45, 225),
        (72, 60, 72, 215),
        (45, 225, 175, 225),
        (105, 95, 105, 195),
        (105, 95, 205, 195),
        (95, 60, 210, 175),
        (210, 175, 260, 65),
        (260, 65, 260, 225),
    ]
    escala = size / 300.0
    grosor = max(0.35, 15 * escala)
    ancho_anterior = getattr(pdf, "line_width", 0.2)

    pdf.set_draw_color(0, 43, 115)
    pdf.set_line_width(grosor)
    for x1, y1, x2, y2 in segmentos:
        pdf.line(
            x + (x1 * escala),
            y + (y1 * escala),
            x + (x2 * escala),
            y + (y2 * escala),
        )
    pdf.set_line_width(ancho_anterior)
    pdf.set_draw_color(0, 0, 0)

class TicketPDF(FPDF):
    def __init__(self, empresa, nit, direccion, telefono, mensaje):
        super().__init__('P', 'mm', 'Letter')
        self.empresa = safe_text(empresa)
        self.nit_val = safe_text(nit)
        self.dir_val = safe_text(direccion)
        self.tel_val = safe_text(telefono)
        self.mensaje = safe_text(mensaje)

    def header(self):
        draw_muebleria_logo_pdf(self, x=12, y=8, size=20)
        draw_muebleria_logo_pdf(self, x=184, y=8, size=20)
        self.set_text_color(0, 43, 115)
        self.set_font('Helvetica', 'B', 18)
        self.cell(0, 10, self.empresa, ln=True, align='C')
        self.set_text_color(0, 0, 0)
        self.set_font('Helvetica', '', 9)
        self.cell(0, 5, f'NIT: {self.nit_val}  |  Tel: {self.tel_val}', ln=True, align='C')
        self.cell(0, 5, self.dir_val, ln=True, align='C')
        self.line(10, self.get_y()+3, 206, self.get_y()+3)
        self.ln(6)

    def footer(self):
        self.set_y(-25)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 5, self.mensaje, ln=True, align='C')
        self.cell(0, 5, safe_text(f'Pagina {self.page_no()}'), align='C')

class GuiaPDF(FPDF):
    def __init__(self, empresa):
        super().__init__('P', 'mm', 'Letter')
        self.empresa = safe_text(empresa)

    def header(self):
        draw_muebleria_logo_pdf(self, x=12, y=8, size=18)
        draw_muebleria_logo_pdf(self, x=186, y=8, size=18)
        self.set_text_color(0, 43, 115)
        self.set_font('Helvetica', 'B', 16)
        self.cell(0, 10, safe_text(f'{self.empresa} - GUIA DE DESPACHO'), ln=True, align='C')
        self.set_text_color(0, 0, 0)
        self.line(10, self.get_y()+2, 206, self.get_y()+2)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 5, safe_text(f'Documento interno - Pagina {self.page_no()}'), align='C')

@app.route("/imprimir_ticket/<int:venta_id>")
@login_required
def imprimir_ticket(venta_id):
    v = Venta.query.get_or_404(venta_id)
    conf = Configuracion.query.first() or Configuracion()
    items = agrupar_items_venta(v)

    cotizacion_forzada = (request.args.get("cotizacion") == "1")
    preview_cotizacion = (request.args.get("preview") == "1")
    es_cotizacion = cotizacion_forzada or (v.estado == 'Cotizacion')
    notas_ticket = v.notas or ""
    if cotizacion_forzada and preview_cotizacion:
        draft = session.get("cotizacion_preview")
        if isinstance(draft, dict):
            try:
                draft_vid = int(draft.get("venta_id") or 0)
            except Exception:
                draft_vid = 0
            if draft_vid == v.id:
                notas_ticket = (draft.get("notas") or notas_ticket).strip()
        # Consumir preview para no reutilizar notas de otra operación.
        session.pop("cotizacion_preview", None)
    
    pdf = TicketPDF(
        conf.nombre_empresa, conf.nit, conf.direccion,
        conf.telefono, conf.mensaje_ticket
    )
    pdf.add_page()

    # Tipo de documento
    if es_cotizacion:
        pdf.set_fill_color(193, 154, 107) # Bronze
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.cell(0, 10, 'COTIZACION / PRESUPUESTO EXCLUSIVO', ln=True, align='C', fill=True)
        pdf.set_text_color(100, 100, 100)
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, safe_text('Este documento tiene validez de 15 dias. No es valido como factura de venta.'), ln=True, align='C')
        pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_fill_color(15, 23, 42) # Slate Deep
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.cell(0, 10, safe_text(f'COMPROBANTE DE VENTA ELITE #{v.id}'), ln=True, align='C', fill=True)
        pdf.set_text_color(0, 0, 0)
    
    pdf.ln(4)

    # Info cliente (con respaldo desde crédito asociado, por si venta.cliente fue desvinculado)
    cliente_ticket = v.cliente
    if not cliente_ticket and v.creditos:
        cliente_ticket = v.creditos[0].cliente

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, 'Cliente:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, safe_text(cliente_ticket.nombre if cliente_ticket else 'Consumidor Final'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, safe_text('Telefono:'), 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, safe_text(cliente_ticket.telefono if cliente_ticket and cliente_ticket.telefono else '---'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, safe_text('CC/NIT:'), 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, safe_text(cliente_ticket.documento if cliente_ticket and cliente_ticket.documento else '---'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, safe_text('Direccion:'), 0)
    pdf.set_font('Helvetica', '', 10)
    direccion_ticket = v.direccion_envio or (cliente_ticket.direccion if cliente_ticket else None)
    pdf.cell(0, 6, safe_text(direccion_ticket if direccion_ticket else '---'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, 'Fecha:', 0)
    pdf.set_font('Helvetica', '', 10)
    fecha_str = v.fecha_cierre.strftime('%d/%m/%Y %H:%M') if v.fecha_cierre else v.fecha_creacion.strftime('%d/%m/%Y %H:%M')
    pdf.cell(0, 6, fecha_str, ln=True)

    if v.vendedor:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(30, 6, 'Vendedor:', 0)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 6, safe_text(v.vendedor.username), ln=True)

    pdf.ln(4)

    # Tabla de items
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(15, 8, 'Cant', 1, 0, 'C', True)
    pdf.cell(95, 8, safe_text('Descripcion'), 1, 0, 'L', True)
    pdf.cell(40, 8, 'P. Unit', 1, 0, 'R', True)
    pdf.cell(46, 8, 'Subtotal', 1, 1, 'R', True)

    pdf.set_font('Helvetica', '', 10)
    subtotal_items = 0
    for item in items:
        subtotal = item['cantidad'] * item['precio']
        subtotal_items += subtotal
        pdf.cell(15, 7, str(item['cantidad']), 1, 0, 'C')
        nombre_item = safe_text(item['nombre'])
        if item.get('notas'):
            nombre_item += safe_text(f" ({item['notas']})")
        pdf.cell(95, 7, nombre_item[:50], 1, 0, 'L')
        pdf.cell(40, 7, f"${item['precio']:,.0f}", 1, 0, 'R')
        pdf.cell(46, 7, f"${subtotal:,.0f}", 1, 1, 'R')

    descuento_ticket = max(subtotal_items - int(v.total or 0), 0)
    if descuento_ticket > 0:
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(150, 7, 'Descuento contado:', 1, 0, 'R')
        pdf.cell(46, 7, f"-${descuento_ticket:,.0f}", 1, 1, 'R')

    # Total
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(150, 10, 'TOTAL:', 1, 0, 'R')
    pdf.cell(46, 10, f"${v.total:,.0f}", 1, 1, 'R')
    pdf.ln(3)

    # Desglose de pago (solo si no es cotizacion)
    if not es_cotizacion:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(0, 7, safe_text(f'Metodo de Pago: {v.metodo_pago or "---"}'), ln=True)

        if v.metodo_pago == 'Mixto':
            pdf.set_font('Helvetica', '', 9)
            if v.pago_efectivo:
                pdf.cell(0, 6, f'  Efectivo: ${v.pago_efectivo:,.0f}', ln=True)
            if v.pago_tarjeta:
                pdf.cell(0, 6, f'  Tarjeta: ${v.pago_tarjeta:,.0f}', ln=True)
            if v.pago_transferencia:
                pdf.cell(0, 6, f'  Transferencia: ${v.pago_transferencia:,.0f}', ln=True)
        elif v.metodo_pago == 'Credito' and v.creditos:
            credito = v.creditos[0]
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(0, 6, f'  Cuota Inicial: ${credito.cuota_inicial:,.0f}', ln=True)
            pdf.cell(0, 6, f'  Total Financiado: ${credito.total_financiado:,.0f}', ln=True)
            pdf.cell(0, 6, f'  Plan: {credito.numero_cuotas} cuotas {credito.periodicidad.lower()}s de ${credito.valor_cuota:,.0f}', ln=True)

        if v.monto_recibido and v.monto_recibido > 0 and v.metodo_pago != 'Credito':
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 6, f'Monto Recibido: ${v.monto_recibido:,.0f}', ln=True)
        
        if v.cambio and v.cambio > 0:
            pdf.cell(0, 6, f'Cambio: ${v.cambio:,.0f}', ln=True)

        saldo = v.total - (v.monto_recibido or 0)
        if saldo > 0 and v.metodo_pago != 'Credito':
            pdf.ln(3)
            pdf.set_fill_color(255, 241, 242) # Light Red
            pdf.set_text_color(153, 27, 27) # Deep Red
            pdf.set_font('Helvetica', 'B', 11)
            pdf.cell(0, 8, safe_text(f'  SALDO PENDIENTE CARTERA: ${saldo:,.0f}'), ln=True, fill=True)
            pdf.set_text_color(0, 0, 0)

    # Notas
    if notas_ticket:
        pdf.ln(3)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, 'Notas:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 5, safe_text(notas_ticket))

    # Generar PDF
    import io
    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    
    tipo_doc = "Cotizacion" if es_cotizacion else "Ticket"
    response = make_response(buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename={tipo_doc}_{v.id}.pdf'
    return response

@app.route("/imprimir_abono/<int:abono_id>")
@login_required
def imprimir_abono(abono_id):
    abono = AbonoCredito.query.get_or_404(abono_id)
    conf = Configuracion.query.first() or Configuracion()
    credito = abono.credito
    cliente = credito.cliente

    pdf = TicketPDF(
        conf.nombre_empresa, conf.nit, conf.direccion,
        conf.telefono, conf.mensaje_ticket
    )
    pdf.add_page()

    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, safe_text(f'RECIBO DE CAJA #{abono.id}'), ln=True, align='C', fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, 'Fecha:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, abono.fecha.strftime('%d/%m/%Y %H:%M'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, 'Cliente:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, safe_text(cliente.nombre if cliente else '---'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(30, 6, 'Credito:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, safe_text(credito.codigo), ln=True)

    if abono.numero_cuota:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(30, 6, 'Cuota No.:', 0)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 6, str(abono.numero_cuota), ln=True)

    pdf.ln(4)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(100, 10, safe_text('VALOR RECIBIDO:'), 1, 0, 'R')
    pdf.cell(0, 10, f"${abono.monto:,.0f}", 1, 1, 'R')

    pdf.set_font('Helvetica', '', 10)
    pdf.cell(100, 8, safe_text('SALDO PENDIENTE DEL CREDITO:'), 1, 0, 'R')
    pdf.cell(0, 8, f"${abono.saldo_posterior:,.0f}", 1, 1, 'R')

    if abono.metodo_pago:
        pdf.ln(3)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 6, safe_text(f'Forma de pago: {abono.metodo_pago}'), ln=True)

    if abono.nota:
        pdf.ln(2)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, 'Notas:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 5, safe_text(abono.nota))

    import io
    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    
    response = make_response(buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=Recibo_{abono.id}.pdf'
    return response

@app.route("/imprimir_guia/<int:venta_id>")
@login_required
def imprimir_guia(venta_id):
    v = Venta.query.get_or_404(venta_id)
    conf = Configuracion.query.first() or Configuracion()
    items = agrupar_items_venta(v)

    pdf = GuiaPDF(conf.nombre_empresa)
    pdf.add_page()

    # Datos del despacho
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, safe_text(f'Venta #: {v.id}'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(35, 7, 'Fecha:', 0)
    pdf.set_font('Helvetica', '', 10)
    fecha_str = v.fecha_cierre.strftime('%d/%m/%Y %H:%M') if v.fecha_cierre else '---'
    pdf.cell(0, 7, fecha_str, ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(35, 7, 'Sede Origen:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, safe_text(v.sede.nombre if v.sede else '---'), ln=True)

    pdf.ln(3)
    pdf.set_fill_color(15, 23, 42) # Slate
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, '  DETALLES DEL DESTINATARIO Y ENTREGA', ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(35, 7, 'Cliente:', 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, safe_text(v.cliente.nombre if v.cliente else 'Consumidor Final'), ln=True)

    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(35, 7, safe_text('Telefono:'), 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, safe_text(v.cliente.telefono if v.cliente else '---'), ln=True)

    direccion_entrega = v.direccion_envio or (v.cliente.direccion if v.cliente else 'Sin direccion')
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(35, 7, safe_text('Direccion:'), 0)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, safe_text(direccion_entrega), ln=True)

    pdf.ln(5)

    # Tabla de articulos (SIN precios)
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(20, 8, 'Cant', 1, 0, 'C', True)
    pdf.cell(130, 8, safe_text('Articulo / Descripcion'), 1, 0, 'L', True)
    pdf.cell(46, 8, 'Notas', 1, 1, 'L', True)

    pdf.set_font('Helvetica', '', 10)
    for item in items:
        pdf.cell(20, 7, str(item['cantidad']), 1, 0, 'C')
        pdf.cell(130, 7, safe_text(item['nombre'])[:65], 1, 0, 'L')
        pdf.cell(46, 7, safe_text(item.get('notas', '') or '')[:25], 1, 1, 'L')

    # Notas de venta
    if v.notas:
        pdf.ln(4)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, 'Observaciones:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 5, safe_text(v.notas))

    # Zona de firmas
    pdf.ln(20)
    x_left = 25
    x_right = 120
    line_y = pdf.get_y()
    pdf.line(x_left, line_y, x_left + 65, line_y)
    pdf.line(x_right, line_y, x_right + 65, line_y)

    pdf.set_font('Helvetica', '', 9)
    pdf.set_xy(x_left, line_y + 2)
    pdf.cell(65, 5, 'Firma Transportista', 0, 0, 'C')
    pdf.set_xy(x_right, line_y + 2)
    pdf.cell(65, 5, 'Firma Recibido Conforme', 0, 0, 'C')

    pdf.set_xy(x_left, line_y + 8)
    pdf.cell(65, 5, 'Nombre: ___________________', 0, 0, 'L')
    pdf.set_xy(x_right, line_y + 8)
    pdf.cell(65, 5, 'Nombre: ___________________', 0, 0, 'L')

    pdf.set_xy(x_left, line_y + 14)
    pdf.cell(65, 5, 'C.C.: _____________________', 0, 0, 'L')
    pdf.set_xy(x_right, line_y + 14)
    pdf.cell(65, 5, 'C.C.: _____________________', 0, 0, 'L')

    # Generar PDF
    import io
    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    
    response = make_response(buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=Guia_Despacho_{v.id}.pdf'
    return response

@app.route("/admin/descargar_cierre_pdf")
@admin_required
def descargar_cierre_pdf():
    fecha_str = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    st = datetime.strptime(fecha_str, '%Y-%m-%d').replace(hour=0, minute=0)
    en = datetime.strptime(fecha_str, '%Y-%m-%d').replace(hour=23, minute=59)

    ventas = Venta.query.filter(Venta.cerrado == True, Venta.fecha_cierre >= st, Venta.fecha_cierre <= en).all()
    gastos = Gasto.query.filter(Gasto.fecha >= st, Gasto.fecha <= en).all()
    conf = Configuracion.query.first() or Configuracion()

    pdf = TicketPDF(conf.nombre_empresa, conf.nit, conf.direccion, conf.telefono, "REPORTE DE CIERRE DIARIO")
    pdf.add_page()
    
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, safe_text(f'CIERRE DE CAJA - FECHA: {fecha_str}'), ln=True, align='C')
    pdf.ln(5)

    te = sum(v.total for v in ventas if v.metodo_pago == 'Efectivo')
    td = sum(v.total for v in ventas if v.metodo_pago != 'Efectivo')
    tg = sum(g.monto for g in gastos)

    # Resumen Financiero
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, ' RESUMEN FINANCIERO', ln=True, fill=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(100, 7, 'Efectivo en Ventas:', 0)
    pdf.cell(0, 7, f'${te:,.0f}', ln=True, align='R')
    pdf.cell(100, 7, 'Digital / Transferencias:', 0)
    pdf.cell(0, 7, f'${td:,.0f}', ln=True, align='R')
    pdf.cell(100, 7, 'Total Egresos (Gastos):', 0)
    pdf.cell(0, 7, f'-${tg:,.0f}', ln=True, align='R')
    pdf.ln(2)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(100, 8, 'TOTAL NETO DEL DIA:', 0)
    pdf.cell(0, 8, f'${(te+td-tg):,.0f}', ln=True, align='R')
    pdf.ln(10)

    # Detalle de Ventas
    pdf.set_fill_color(230, 240, 255)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, ' DETALLE DE VENTAS', ln=True, fill=True)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(20, 7, 'Venta #', 1, 0, 'C')
    pdf.cell(40, 7, 'Sede', 1, 0, 'L')
    pdf.cell(40, 7, 'Metodo', 1, 0, 'L')
    pdf.cell(40, 7, 'Cliente', 1, 0, 'L')
    pdf.cell(0, 7, 'Monto', 1, 1, 'R')
    
    pdf.set_font('Helvetica', '', 8)
    for v in ventas:
        pdf.cell(20, 6, str(v.id), 1, 0, 'C')
        pdf.cell(40, 6, safe_text(v.sede.nombre[:20] if v.sede else '---'), 1, 0, 'L')
        pdf.cell(40, 6, safe_text(v.metodo_pago or '---'), 1, 0, 'L')
        pdf.cell(40, 6, safe_text(v.cliente.nombre[:20] if v.cliente else 'General'), 1, 0, 'L')
        pdf.cell(0, 6, f'${v.total:,.0f}', 1, 1, 'R')

    import io
    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"Cierre_{fecha_str}.pdf", mimetype='application/pdf')

@app.errorhandler(404)
def page_not_found(e):
    # Evitar confundir 404 con "sesión cerrada" cuando el usuario ya está autenticado.
    if request.path.startswith("/static/"):
        return "Not Found", 404
    if session.get("user_id"):
        flash("Ruta no encontrada. Te llevamos al inicio.", "warning")
        return redirect(url_for("index"))
    return render_template('login.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    flash("Ocurrió un error interno. La operación ha sido cancelada para proteger sus datos.", "danger")
    return redirect(url_for('index')), 500

@app.route("/admin/backup_db")
@admin_required
def backup_db():
    try:
        if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
            flash("El respaldo directo del archivo .db solo aplica cuando el sistema usa SQLite.", "info")
            return redirect(request.referrer or url_for('admin'))
        db_path = local_db_path
        if os.path.exists(db_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"RESPALDO_POS_{timestamp}.db"
            registrar_auditoria("Respaldo", f"Generado respaldo manual: {filename}")
            return send_file(db_path, as_attachment=True, download_name=filename)
        else:
            flash("Archivo de base de datos no encontrado.", "warning")
    except Exception as e:
        flash(f"Error al generar respaldo: {e}", "danger")
    return redirect(request.referrer or url_for('admin'))

if __name__ == "__main__":
    crear_datos_iniciales()
    # En uso normal mantenemos desactivado el hot reload para no perder contexto en POS.
    # Si necesitas modo desarrollo, activa estas variables:
    #   POS_DEBUG=1
    #   POS_HOT_RELOAD=1
    debug_mode = os.environ.get("POS_DEBUG", "0") == "1"
    # Blindaje: evitar hot-reload para no perder contexto y evitar procesos duplicados.
    hot_reload = False
    port = int(os.environ.get("PORT", "5001"))
    print(f"[POS] build=render-ready pid={os.getpid()} debug={debug_mode} reloader={hot_reload} db={app.config['SQLALCHEMY_DATABASE_URI'].split(':', 1)[0]}")
    app.run(host="0.0.0.0", port=port, debug=debug_mode, use_reloader=hot_reload)
