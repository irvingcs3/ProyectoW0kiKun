# app.py
import customtkinter as ctk
from tkinter import messagebox
from usuario import Usuario
from auth_utils import hash_password, USUARIOS_REGISTRADOS, NEXT_USER_ID

# --- Lógica de Autenticación Segura ---

def registrar_usuario(nombre_usuario: str, password: str):
    """Registra un nuevo usuario, hasheando la contraseña antes de guardarla."""
    global NEXT_USER_ID
    
    if not (4 <= len(password) <= 20):
        return False, "La contraseña debe tener entre 4 y 20 caracteres."
    
    if any(u.nombre_usuario == nombre_usuario for u in USUARIOS_REGISTRADOS):
        return False, f"El usuario '{nombre_usuario}' ya existe."

    # 1. GENERACIÓN SEGURA: Obtener el hash y el salt
    password_hash, salt = hash_password(password)

    # 2. Almacenar el hash y el salt
    nuevo_usuario = Usuario(
        id=NEXT_USER_ID,
        nombre_usuario=nombre_usuario,
        password_hash=password_hash,
        salt=salt
    )
    USUARIOS_REGISTRADOS.append(nuevo_usuario)
    NEXT_USER_ID += 1
    
    return True, f"Usuario '{nombre_usuario}' registrado con ID: {nuevo_usuario.id}"


def iniciar_sesion(nombre_usuario: str, password: str) -> (bool, str):
    """Verifica la contraseña comparando hashes (Autenticación real)."""
    
    # 1. Buscar usuario y recuperar el hash y salt almacenados
    usuario = next(
        (u for u in USUARIOS_REGISTRADOS if u.nombre_usuario == nombre_usuario),
        None
    )

    if not usuario:
        # Evitar dar pistas sobre si el usuario existe o no
        return False, "Usuario o contraseña incorrectos."
        
    # 2. CALCULAR HASH DE PRUEBA: Hashear la contraseña ingresada con el salt ALMACENADO
    hash_prueba, _ = hash_password(password, salt=usuario.salt)
    
    # 3. COMPARACIÓN SEGURA
    if hash_prueba == usuario.password_hash:
        return True, f"¡Bienvenido, {nombre_usuario}! Acceso Autorizado."
    else:
        return False, "Usuario o contraseña incorrectos."

# --- Interfaz Gráfica (CustomTkinter) ---

class AuthApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # 1. Configuración de la Ventana
        self.title("🛡️ Proyecto Criptográfico - Login Seguro")
        self.geometry("400x400")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # 2. Marco Principal (Contenedor de widgets)
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(pady=40, padx=40, fill="both", expand=True) 

        # 3. Widgets
        self.label = ctk.CTkLabel(self.main_frame, text="ACCESO REQUERIDO", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        self.label.pack(pady=10)

        self.username_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Nombre de Usuario")
        self.username_entry.pack(pady=12, padx=10)

        self.password_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Contraseña", show="*")
        self.password_entry.pack(pady=12, padx=10)

        self.login_button = ctk.CTkButton(self.main_frame, text="Iniciar Sesión", command=self.handle_login)
        self.login_button.pack(pady=10, padx=10)

        self.register_button = ctk.CTkButton(self.main_frame, text="Registrar Nuevo Usuario", 
                                             command=self.handle_register, fg_color="#3B8ED0", hover_color="#36719F")
        self.register_button.pack(pady=5, padx=10)
        

    def handle_login(self):
        """Maneja el evento de inicio de sesión."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        success, message = iniciar_sesion(username, password)
        
        if success:
            messagebox.showinfo("Autorización Exitosa", message)
            self.clear_fields()
        else:
            messagebox.showerror("Autorización Fallida", message)
    
    def handle_register(self):
        """Maneja el evento de registro de usuario."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        success, message = registrar_usuario(username, password)
        
        if success:
            messagebox.showinfo("Registro Exitoso", message)
            self.clear_fields()
        else:
            messagebox.showerror("Fallo de Registro", message)

    def clear_fields(self):
        """Limpia los campos de entrada."""
        self.username_entry.delete(0, 'end')
        self.password_entry.delete(0, 'end')


if __name__ == "__main__":
    app = AuthApp()
    app.mainloop()