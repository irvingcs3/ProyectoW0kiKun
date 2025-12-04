from typing import List, Optional, Tuple
from rsa_utils import generar_par_claves_rsa, firmar_archivo
from crypto_utils import hash_password, verify_password
from hash_utils import hash_archivo
from aes_hybrid import cifrar_con_aes_maestra
from models import KeyPair, User
from db import get_connection
from mysql.connector import Error
import os

# =============================
#   USUARIOS
# =============================

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


# =============================
#   LLAVES RSA
# =============================

def generate_and_store_keys(user: User) -> KeyPair:
    public_key, private_key = generar_par_claves_rsa()

    conn = get_connection()
    cursor = conn.cursor()

    # Usamos REPLACE para actualizar si ya existe o insertar si no
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


# =============================
#   PROYECTOS Y PERMISOS
# =============================

def store_project_file(user: User, original_path: str, encrypted_path: str):
    """
    (Función Legacy) Crea un proyecto NUEVO desde cero.
    """
    filename = os.path.basename(original_path)

    conn = get_connection()
    cursor = conn.cursor()

    # Nota: Aquí no estamos asignando clave maestra real, solo insertando para compatibilidad
    # Para el flujo real, se debe usar subir_archivo_con_llave_local sobre un proyecto existente
    cursor.execute("""
        INSERT INTO Proyectos (nombre_proyecto, clave_AES_maestra, ubicacion_codigo_cifrado)
        VALUES (%s, 'CLAVE_DUMMY_PARA_LEGACY', %s)
    """, (filename, encrypted_path))

    proyecto_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO Permisos_Usuario_Proyecto (id_proyecto, id_usuario, permiso)
        VALUES (%s, %s, 'ESCRITURA')
    """, (proyecto_id, user.id))

    conn.commit()
    cursor.close()
    conn.close()

    return proyecto_id


def get_projects_for_user(user: User):
    """Obtiene proyectos donde el usuario tiene algun permiso (Lectura o Escritura)"""
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


# --- NUEVAS FUNCIONES PARA EL FLUJO SEGURO ---

def obtener_proyectos_escritura(id_usuario: int):
    """
    Obtiene lista de proyectos donde el usuario tiene permiso explícito de ESCRITURA.
    """
    conn = get_connection()
    if not conn: return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT p.id_proyecto, p.nombre_proyecto 
            FROM proyectos p
            JOIN permisos_usuario_proyecto pup ON p.id_proyecto = pup.id_proyecto
            WHERE pup.id_usuario = %s AND pup.permiso = 'ESCRITURA'
        """
        cursor.execute(query, (id_usuario,))
        return cursor.fetchall()
    except Error as e:
        print(f"Error BD: {e}")
        return []
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def subir_archivo_con_llave_local(id_usuario, id_proyecto, ruta_archivo, ruta_llave_privada):
    """
    Orquesta la subida segura:
    1. Valida permiso en BD.
    2. Obtiene llave AES de BD.
    3. Firma usando la llave privada LOCAL (del archivo).
    4. Cifra y guarda en BD.
    """
    conn = get_connection()
    if not conn: return False, "Error de conexión a la Base de Datos"
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # A. VALIDAR PERMISO DE ESCRITURA
        cursor.execute("""
            SELECT permiso FROM permisos_usuario_proyecto 
            WHERE id_usuario=%s AND id_proyecto=%s AND permiso='ESCRITURA'
        """, (id_usuario, id_proyecto))
        
        if not cursor.fetchone():
            return False, "⛔ ACCESO DENEGADO: No tienes permiso de ESCRITURA en este proyecto."

        # B. OBTENER CLAVE MAESTRA AES DEL PROYECTO
        cursor.execute("SELECT clave_AES_maestra FROM proyectos WHERE id_proyecto=%s", (id_proyecto,))
        row_proj = cursor.fetchone()
        if not row_proj: return False, "El proyecto no existe."
        
        clave_aes = row_proj['clave_AES_maestra'] # Bytes desde MySQL

        # C. FIRMA DIGITAL (Cliente)
        # 1. Leemos la llave privada del disco (CLIENTE)
        with open(ruta_llave_privada, "rb") as f:
            pem_privada_str = f.read().decode('utf-8')
        
        # 2. Calculamos Hash
        hash_val = hash_archivo(ruta_archivo)
        
        # 3. Firmamos (Tu función rsa_utils guarda el .sig en disco, leemos eso)
        ruta_sig = firmar_archivo(ruta_archivo, pem_privada_str)
        
        # 4. Leemos la firma generada para poder guardarla en la BD
        with open(ruta_sig, "rb") as f:
            firma_bytes = f.read() 

        # D. CIFRADO (Servidor/Híbrido)
        # Ciframos el archivo usando la llave maestra del proyecto
        ruta_enc = cifrar_con_aes_maestra(ruta_archivo, clave_aes)

        # E. ACTUALIZAR BASE DE DATOS
        # 1. Actualizar ubicación del archivo cifrado en tabla Proyectos
        cursor.execute("UPDATE proyectos SET ubicacion_codigo_cifrado=%s WHERE id_proyecto=%s", (ruta_enc, id_proyecto))
        
        # 2. Registrar el evento en Auditoría de Firmas
        sql_audit = """
            INSERT INTO auditoria_firmas 
            (id_proyecto, id_usuario, firma_RSA, hash_del_codigo_aceptado, fecha)
            VALUES (%s, %s, %s, %s, NOW())
        """
        cursor.execute(sql_audit, (id_proyecto, id_usuario, firma_bytes, hash_val))
        
        conn.commit()
        return True, f"✅ Archivo subido exitosamente.\nIntegridad (Hash): {hash_val[:10]}..."

    except Exception as e:
        print(f"Error detallado: {e}")
        return False, f"Error del sistema: {str(e)}"
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def download_project_file(proyecto_id: int):
    """
    Obtiene la ruta del archivo y la CLAVE AES MAESTRA para poder descifrarlo.
    Retorna: (ubicacion_cifrada, clave_aes_maestra)
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ubicacion_codigo_cifrado, clave_AES_maestra
        FROM Proyectos
        WHERE id_proyecto = %s
    """, (proyecto_id,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return None, None

    return row["ubicacion_codigo_cifrado"], row["clave_AES_maestra"]