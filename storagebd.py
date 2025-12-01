from typing import List, Optional, Tuple
from rsa_utils import generar_par_claves_rsa
from crypto_utils import hash_password, verify_password
from models import KeyPair, User
from db import get_connection
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

    cursor.execute("""
        INSERT INTO Usuarios (nombre, password_hash, salt, esta_activo)
        VALUES (%s, %s, %s, TRUE)
    """, (username, password_hash, salt))

    conn.commit()
    user_id = cursor.lastrowid

    cursor.close()
    conn.close()

    return True, f"Usuario '{username}' creado.", User(
        id=user_id,
        username=username,
        password_hash=password_hash,
        salt=salt
    )


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
    Registra un proyecto real en MySQL:
    - Guarda el proyecto en tabla Proyectos
    - Asigna permiso ESCRITURA al usuario que lo subió
    """

    filename = os.path.basename(original_path)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO Proyectos (nombre_proyecto, clave_AES_maestra, ubicacion_codigo_cifrado)
        VALUES (%s, NULL, %s)
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


def download_project_file(proyecto_id: int) -> Optional[str]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ubicacion_codigo_cifrado
        FROM Proyectos
        WHERE id_proyecto = %s
    """, (proyecto_id,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return None

    return row["ubicacion_codigo_cifrado"]
