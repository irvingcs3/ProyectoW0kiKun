from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rsa_utils import generar_par_claves_rsa, firmar_archivo, verificar_firma
from crypto_utils import hash_password, verify_password
from hash_utils import hash_archivo
from aes_hybrid import cifrar_con_aes_maestra
from models import KeyPair, User
from db import get_connection
from mysql.connector import Error
import os

# ============================================================
#   GESTIÓN DE USUARIOS
# ============================================================

def create_user(username: str, password: str) -> Tuple[bool, str, Optional[User]]:
    if len(password) < 4 or len(password) > 20:
        return False, "La contraseña debe tener entre 4 y 20 caracteres.", None

    if find_user_by_username(username):
        return False, "El usuario ya existe.", None

    password_hash, salt = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO Usuarios (nombre, password_hash, salt, esta_activo)
            VALUES (%s, %s, %s, TRUE)
        """, (username, password_hash, salt))

        conn.commit()
        user_id = cursor.lastrowid
        
        return True, f"Usuario '{username}' creado.", User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            salt=salt
        )
    except Error as e:
        return False, f"Error BD: {e}", None
    finally:
        cursor.close()
        conn.close()


def find_user_by_username(username: str) -> Optional[User]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id_usuario, nombre, password_hash, salt, esta_activo
        FROM Usuarios
        WHERE nombre = %s
    """, (username,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return None

    return User(
        id=row["id_usuario"],
        username=row["nombre"],
        password_hash=row["password_hash"],
        salt=row["salt"],
        active=row["esta_activo"]
    )


def authenticate(username: str, password: str):
    user = find_user_by_username(username)
    if not user:
        return False, "Usuario o contraseña incorrectos.", None

    if not verify_password(password, user.password_hash, user.salt):
        return False, "Usuario o contraseña incorrectos.", None

    if not user.active:
        return False, "El usuario está inactivo.", None

    return True, f"Bienvenido, {user.username}.", user


def update_password(user: User, old_password: str, new_password: str):
    if not verify_password(old_password, user.password_hash, user.salt):
        return False, "La contraseña actual no es correcta."

    if len(new_password) < 4 or len(new_password) > 20:
        return False, "La contraseña debe tener entre 4 y 20 caracteres."

    new_hash, new_salt = hash_password(new_password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE Usuarios
        SET password_hash = %s, salt = %s
        WHERE id_usuario = %s
    """, (new_hash, new_salt, user.id))

    conn.commit()
    cursor.close()
    conn.close()

    user.password_hash = new_hash
    user.salt = new_salt

    return True, "Contraseña actualizada correctamente."


def list_users() -> List[User]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id_usuario, nombre, password_hash, salt, esta_activo
        FROM Usuarios
    """)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return [
        User(
            id=row["id_usuario"],
            username=row["nombre"],
            password_hash=row["password_hash"],
            salt=row["salt"],
            active=row["esta_activo"]
        )
        for row in rows
    ]


# ============================================================
#   GESTIÓN DE LLAVES RSA
# ============================================================

def generate_and_store_keys(user: User) -> KeyPair:
    public_key, private_key = generar_par_claves_rsa()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        REPLACE INTO LlavesRSA (id_usuario, llave_publica, llave_privada)
        VALUES (%s, %s, %s)
    """, (user.id, public_key, private_key))

    conn.commit()

    cursor.close()
    conn.close()

    return KeyPair(user_id=user.id, public_key=public_key, private_key=private_key)


def get_keys_for_user(user: User) -> Optional[KeyPair]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT llave_publica, llave_privada
        FROM LlavesRSA
        WHERE id_usuario = %s
    """, (user.id,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return None

    return KeyPair(
        user_id=user.id,
        public_key=row["llave_publica"],
        private_key=row["llave_privada"],
    )


def user_has_keys(user: User) -> bool:
    return get_keys_for_user(user) is not None


# ============================================================
#   GESTIÓN DE PROYECTOS Y PERMISOS (Lectura General)
# ============================================================

def obtener_proyectos_escritura(id_usuario: int):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.id_proyecto, p.nombre_proyecto
        FROM Proyectos p
        JOIN Permisos_Usuario_Proyecto pup
            ON p.id_proyecto = pup.id_proyecto
        WHERE pup.id_usuario = %s AND pup.permiso = 'ESCRITURA'
    """, (id_usuario,))

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows


def get_projects_for_user(user: User):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.id_proyecto, p.nombre_proyecto, p.ubicacion_codigo_cifrado
        FROM Proyectos p
        JOIN Permisos_Usuario_Proyecto pup
            ON p.id_proyecto = pup.id_proyecto
        WHERE pup.id_usuario = %s
    """, (user.id,))

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows


# ============================================================
#   ADMINISTRACIÓN DE PROYECTOS Y LLAVES
# ============================================================

def obtener_todos_los_proyectos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id_proyecto, nombre_proyecto FROM Proyectos")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def crear_nuevo_proyecto(nombre_proyecto: str, id_admin: int) -> Tuple[bool, str]:
    conn = get_connection()
    if not conn: return False, "Error de conexión."
    
    cursor = conn.cursor()
    try:
        clave_maestra = AESGCM.generate_key(bit_length=256)
        
        cursor.execute("""
            INSERT INTO Proyectos (nombre_proyecto, clave_AES_maestra, ubicacion_codigo_cifrado)
            VALUES (%s, %s, '')
        """, (nombre_proyecto, clave_maestra))
        
        id_nuevo_proyecto = cursor.lastrowid
        
        cursor.execute("""
            INSERT INTO Permisos_Usuario_Proyecto (id_proyecto, id_usuario, permiso)
            VALUES (%s, %s, 'ESCRITURA')
        """, (id_nuevo_proyecto, id_admin))
        
        conn.commit()
        return True, f"Proyecto '{nombre_proyecto}' creado exitosamente (ID: {id_nuevo_proyecto})."
        
    except Error as e:
        return False, f"Error al crear proyecto: {e}"
    finally:
        cursor.close()
        conn.close()

def asignar_permiso_proyecto(id_proyecto: int, id_usuario: int, tipo_permiso: str) -> Tuple[bool, str]:
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            REPLACE INTO Permisos_Usuario_Proyecto (id_proyecto, id_usuario, permiso)
            VALUES (%s, %s, %s)
        """, (id_proyecto, id_usuario, tipo_permiso))
        
        conn.commit()
        return True, f"Permiso de {tipo_permiso} asignado correctamente."
    except Error as e:
        return False, f"Error al asignar permiso: {e}"
    finally:
        cursor.close()
        conn.close()

def admin_regenerar_llaves_usuario(id_usuario_objetivo: int) -> Tuple[bool, str, Optional[KeyPair]]:
    conn = get_connection()
    if not conn: return False, "Sin conexión.", None
    
    cursor = conn.cursor()
    try:
        public_key, private_key = generar_par_claves_rsa()
        
        cursor.execute("""
            REPLACE INTO LlavesRSA (id_usuario, llave_publica, llave_privada)
            VALUES (%s, %s, %s)
        """, (id_usuario_objetivo, public_key, private_key))
        
        conn.commit()
        
        nuevo_par = KeyPair(
            user_id=id_usuario_objetivo, 
            public_key=public_key, 
            private_key=private_key
        )
        return True, "Llaves regeneradas exitosamente.", nuevo_par

    except Error as e:
        return False, f"Error BD: {e}", None
    finally:
        cursor.close()
        conn.close()


# ============================================================
#   SUBIDA DE ARCHIVO (ESCRITURA SEGURA)
# ============================================================

def subir_archivo_hibrido(id_usuario, id_proyecto, ruta_archivo, ruta_llave_privada):
    conn = get_connection()
    if not conn: return False, "Error de conexión a la base de datos."
    
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT permiso FROM Permisos_Usuario_Proyecto
            WHERE id_usuario=%s AND id_proyecto=%s AND permiso='ESCRITURA'
        """, (id_usuario, id_proyecto))

        if not cursor.fetchone():
            return False, "Acceso denegado: No tienes permiso de escritura en este proyecto."

        cursor.execute("SELECT llave_publica FROM LlavesRSA WHERE id_usuario=%s", (id_usuario,))
        row_keys = cursor.fetchone()
        if not row_keys:
            return False, "El usuario no tiene llave pública registrada."
        public_pem = row_keys["llave_publica"]

        cursor.execute("SELECT clave_AES_maestra FROM Proyectos WHERE id_proyecto=%s", (id_proyecto,))
        row_proj = cursor.fetchone()
        if not row_proj:
            return False, "Proyecto no encontrado."
        clave_aes = row_proj["clave_AES_maestra"]

        hash_val = hash_archivo(ruta_archivo)

        with open(ruta_llave_privada, "rb") as f:
            private_pem = f.read().decode("utf-8")

        ruta_sig = firmar_archivo(ruta_archivo, private_pem)
        
        if not verificar_firma(ruta_archivo, ruta_sig, public_pem):
            return False, "Error de Integridad: La firma digital no corresponde al archivo o a la identidad del usuario."

        firma_bytes = open(ruta_sig, "rb").read()

        enc_path = cifrar_con_aes_maestra(ruta_archivo, clave_aes)

        cursor.execute("""
            UPDATE Proyectos
            SET ubicacion_codigo_cifrado=%s
            WHERE id_proyecto=%s
        """, (enc_path, id_proyecto))

        cursor.execute("""
            INSERT INTO Auditoria_Firmas
            (id_proyecto, id_usuario, firma_RSA, hash_del_codigo_aceptado, fecha)
            VALUES (%s, %s, %s, %s, NOW())
        """, (id_proyecto, id_usuario, firma_bytes, hash_val))

        conn.commit()
        return True, "Archivo subido, verificado y cifrado correctamente."

    except Exception as e:
        return False, f"Error durante el proceso: {e}"

    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# ============================================================
#   DESCARGA DE ARCHIVO (LECTURA)
# ============================================================

def download_project_file(id_proyecto: int):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ubicacion_codigo_cifrado, clave_AES_maestra
        FROM Proyectos
        WHERE id_proyecto = %s
    """, (id_proyecto,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return None, None

    return row["ubicacion_codigo_cifrado"], row["clave_AES_maestra"]