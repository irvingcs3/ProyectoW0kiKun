from typing import List, Optional, Tuple
from rsa_utils import generar_par_claves_rsa, firmar_archivo
from crypto_utils import hash_password, verify_password
from hash_utils import hash_archivo
from aes_hybrid import cifrar_archivo_hibrido_puro
from models import KeyPair, User
from db import get_connection
from mysql.connector import Error
import os


# ============================================================
#   USUARIOS
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
#   LLAVES RSA
# ============================================================

def generate_and_store_keys(user: User) -> KeyPair:
    public_key, private_key = generar_par_claves_rsa()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        REPLACE INTO LlavesRSA (id_usuario, llave_publica)
        VALUES (%s, %s)
    """, (user.id, public_key))

    conn.commit()

    cursor.close()
    conn.close()

    # Guardamos solo la pública en la BD; la privada se devuelve para guardar localmente
    return KeyPair(user_id=user.id, public_key=public_key, private_key=private_key)



def get_keys_for_user(user: User) -> Optional[KeyPair]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT llave_publica
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
        private_key=None
    )



def user_has_keys(user: User) -> bool:
    return get_keys_for_user(user) is not None



# ============================================================
#   PROYECTOS Y PERMISOS
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
#   SUBIDA HÍBRIDA REAL (AES + RSA)
# ============================================================

def subir_archivo_hibrido(id_usuario, id_proyecto, ruta_archivo, ruta_llave_privada):
    """
    Flujo híbrido real:
    1. Hash del archivo
    2. Firma con llave privada local
    3. Cifrado AES-GCM
    4. Cifrado RSA de la clave AES
    5. Guardar firma + hash + aes_key_cifrada + ruta
    """

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Validar permiso
        cursor.execute("""
            SELECT permiso FROM Permisos_Usuario_Proyecto
            WHERE id_usuario=%s AND id_proyecto=%s AND permiso='ESCRITURA'
        """, (id_usuario, id_proyecto))

        if not cursor.fetchone():
            return False, "No tienes permiso para subir a este proyecto."

        # 2. Obtener llave pública RSA
        cursor.execute("SELECT llave_publica FROM LlavesRSA WHERE id_usuario=%s", (id_usuario,))
        row = cursor.fetchone()
        if not row:
            return False, "El usuario no tiene llave pública registrada."

        public_pem = row["llave_publica"]

        # 3. Hash del archivo
        hash_val = hash_archivo(ruta_archivo)

        # 4. Firma digital
        with open(ruta_llave_privada, "rb") as f:
            private_pem = f.read().decode("utf-8")

        ruta_sig = firmar_archivo(ruta_archivo, private_pem)
        firma_bytes = open(ruta_sig, "rb").read()

        # 5. Cifrado híbrido real
        enc_path, encrypted_aes_key = cifrar_archivo_hibrido_puro(ruta_archivo, public_pem)

        # 6. Guardar información del archivo
        cursor.execute("""
            UPDATE Proyectos
            SET ubicacion_codigo_cifrado=%s,
                clave_AES_maestra=%s
            WHERE id_proyecto=%s
        """, (enc_path, encrypted_aes_key, id_proyecto))

        # 7. Guardar auditoría
        cursor.execute("""
            INSERT INTO Auditoria_Firmas
            (id_proyecto, id_usuario, firma_RSA, hash_del_codigo_aceptado, fecha)
            VALUES (%s, %s, %s, %s, NOW())
        """, (id_proyecto, id_usuario, firma_bytes, hash_val))

        conn.commit()
        return True, "Subida híbrida completada correctamente."

    except Exception as e:
        return False, f"Error durante la subida híbrida: {e}"

    finally:
        cursor.close()
        conn.close()



# ============================================================
#   DESCARGA DE ARCHIVO
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
