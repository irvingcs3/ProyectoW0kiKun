# app.py
from typing import Optional, Tuple

import customtkinter as ctk
from tkinter import messagebox

from auth_utils import (
    ARCHIVOS_CODIGO,
    KEY_PAIRS,
    NEXT_USER_ID,
    USUARIOS_REGISTRADOS,
    change_password,
    generate_rsa_keypair,
    hash_password,
    listar_archivos,
    obtener_archivo_por_id,
    store_code_file,
)
from auth_utils import Usuario


# --- Lógica de Autenticación Segura ---

def registrar_usuario(nombre_usuario: str, password: str):
    """Registra un nuevo usuario, hasheando la contraseña antes de guardarla."""
    global NEXT_USER_ID

    if not (4 <= len(password) <= 20):
        return False, "La contraseña debe tener entre 4 y 20 caracteres."

    if any(u.nombre_usuario == nombre_usuario for u in USUARIOS_REGISTRADOS):
        return False, f"El usuario '{nombre_usuario}' ya existe."

    password_hash, salt = hash_password(password)

    nuevo_usuario = Usuario(
        id=NEXT_USER_ID,
        nombre_usuario=nombre_usuario,
        password_hash=password_hash,
        salt=salt,
    )
    USUARIOS_REGISTRADOS.append(nuevo_usuario)
    NEXT_USER_ID += 1

    return True, f"Usuario '{nombre_usuario}' registrado con ID: {nuevo_usuario.id}"


def iniciar_sesion(nombre_usuario: str, password: str) -> Tuple[bool, str, Optional[Usuario]]:
    """Verifica la contraseña comparando hashes (Autenticación real)."""
    usuario = next((u for u in USUARIOS_REGISTRADOS if u.nombre_usuario == nombre_usuario), None)

    if not usuario:
        return False, "Usuario o contraseña incorrectos.", None

    hash_prueba, _ = hash_password(password, salt=usuario.salt)

    if hash_prueba == usuario.password_hash:
        return True, f"¡Bienvenido, {nombre_usuario}! Acceso Autorizado.", usuario
    return False, "Usuario o contraseña incorrectos.", None


# --- Interfaz Gráfica (CustomTkinter) ---

class AuthApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.current_user: Optional[Usuario] = None

        # Configuración de la Ventana
        self.title("🛡️ Proyecto Criptográfico - Login Seguro")
        self.geometry("900x600")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # Layout principal dividido en información y contenido
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)

        self.info_panel = self._build_info_panel()
        self.info_panel.grid(row=0, column=0, sticky="nsew")

        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.content_frame.rowconfigure(0, weight=1)
        self.content_frame.columnconfigure(0, weight=1)

        self.login_frame = None
        self.dashboard = None

        self.render_login()

    # --- Construcción de UI ---
    def _build_info_panel(self):
        panel = ctk.CTkFrame(self, corner_radius=0)
        panel.rowconfigure(4, weight=1)

        header = ctk.CTkLabel(
            panel,
            text="Servicios Criptográficos",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w",
        )
        header.pack(fill="x", padx=20, pady=(20, 10))

        bullets = (
            "Confidencialidad: AES para proteger el código en reposo.",
            "Integridad: firmas digitales que evidencian cambios.",
            "Autenticación: verificación con contraseñas hasheadas.",
            "Control de acceso: claves RSA para líderes y senior devs.",
        )
        for text in bullets:
            ctk.CTkLabel(panel, text=f"• {text}", justify="left", wraplength=260).pack(
                fill="x", padx=20, pady=4
            )

        highlight = ctk.CTkTextbox(panel, height=180, wrap="word")
        highlight.insert(
            "1.0",
            "Algoritmos propuestos:\n\n"
            "AES → cifra y descifra los archivos.\n"
            "RSA → asigna llaves por usuario.\n"
            "Firma digital (hash + RSA) → detecta modificaciones no autorizadas.",
        )
        highlight.configure(state="disabled")
        highlight.pack(fill="both", expand=True, padx=20, pady=20)

        return panel

    def render_login(self):
        if self.dashboard:
            self.dashboard.destroy()
        if self.login_frame:
            self.login_frame.destroy()

        self.login_frame = ctk.CTkFrame(self.content_frame, corner_radius=12)
        self.login_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.login_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.login_frame,
            text="ACCESO REQUERIDO",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(pady=(20, 10))

        ctk.CTkLabel(self.login_frame, text="Usuario").pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Nombre de Usuario")
        self.username_entry.pack(pady=8, padx=30, fill="x")

        ctk.CTkLabel(self.login_frame, text="Contraseña").pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Contraseña", show="*")
        self.password_entry.pack(pady=8, padx=30, fill="x")

        actions = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        actions.pack(pady=15)
        ctk.CTkButton(actions, text="Iniciar Sesión", command=self.handle_login, width=150).pack(
            side="left", padx=10
        )
        ctk.CTkButton(
            actions,
            text="Registrar Nuevo Usuario",
            command=self.handle_register,
            fg_color="#3B8ED0",
            hover_color="#2F6FA3",
            width=160,
        ).pack(side="left", padx=10)

        self.status_label = ctk.CTkLabel(self.login_frame, text="", text_color="gray")
        self.status_label.pack(pady=(10, 20))

    def render_dashboard(self):
        if self.login_frame:
            self.login_frame.destroy()
        if self.dashboard:
            self.dashboard.destroy()

        self.dashboard = ctk.CTkFrame(self.content_frame, corner_radius=12)
        self.dashboard.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.dashboard.rowconfigure(0, weight=1)
        self.dashboard.columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            self.dashboard,
            text=f"Panel Seguro · {self.current_user.nombre_usuario}",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w",
        )
        header.pack(fill="x", padx=20, pady=(20, 10))

        self.tabview = ctk.CTkTabview(self.dashboard)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self._build_keys_tab()
        self._build_password_tab()
        self._build_files_tab()

    def _build_keys_tab(self):
        tab = self.tabview.add("Llaves RSA")
        tab.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            tab,
            text="Genera y almacena un par de llaves (pública/privada) para el usuario autenticado.",
            wraplength=500,
            justify="left",
        ).pack(pady=(20, 10), padx=20)

        self.keys_result = ctk.CTkTextbox(tab, height=160)
        self.keys_result.insert("1.0", "Presiona el botón para generar las llaves RSA.")
        self.keys_result.configure(state="disabled")
        self.keys_result.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(tab, text="Generar llaves RSA", command=self.handle_generate_keys).pack(pady=10)

        if self.current_user.id in KEY_PAIRS:
            self._render_keys(KEY_PAIRS[self.current_user.id])

    def _render_keys(self, pair):
        self.keys_result.configure(state="normal")
        self.keys_result.delete("1.0", "end")
        public_key, private_key = pair
        self.keys_result.insert(
            "1.0",
            f"Llave Pública:\n{public_key}\n\nLlave Privada (mantener segura):\n{private_key}",
        )
        self.keys_result.configure(state="disabled")

    def _build_password_tab(self):
        tab = self.tabview.add("Contraseña")
        tab.columnconfigure(0, weight=1)

        ctk.CTkLabel(tab, text="Actualiza tu contraseña de forma segura.").pack(pady=(20, 10))

        form = ctk.CTkFrame(tab, fg_color="transparent")
        form.pack(fill="x", padx=20)

        ctk.CTkLabel(form, text="Contraseña actual").grid(row=0, column=0, sticky="w", pady=6)
        self.old_password_entry = ctk.CTkEntry(form, show="*")
        self.old_password_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=8)

        ctk.CTkLabel(form, text="Nueva contraseña").grid(row=1, column=0, sticky="w", pady=6)
        self.new_password_entry = ctk.CTkEntry(form, show="*")
        self.new_password_entry.grid(row=1, column=1, sticky="ew", pady=6, padx=8)

        form.columnconfigure(1, weight=1)

        ctk.CTkButton(tab, text="Guardar cambios", command=self.handle_change_password).pack(pady=15)
        self.password_status = ctk.CTkLabel(tab, text="", text_color="gray")
        self.password_status.pack(pady=(0, 20))

    def _build_files_tab(self):
        tab = self.tabview.add("Código Fuente")
        tab.rowconfigure(1, weight=1)
        tab.columnconfigure(0, weight=1)

        upload_frame = ctk.CTkFrame(tab)
        upload_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        upload_frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(upload_frame, text="Nombre del archivo").grid(row=0, column=0, sticky="w", pady=6)
        self.file_name_entry = ctk.CTkEntry(upload_frame, placeholder_text="backend.py / modulo_aes.py ...")
        self.file_name_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=8)

        ctk.CTkLabel(upload_frame, text="Contenido (simulado cifrado con AES)").grid(row=1, column=0, sticky="nw", pady=6)
        self.file_content_box = ctk.CTkTextbox(upload_frame, height=120)
        self.file_content_box.grid(row=1, column=1, sticky="ew", pady=6, padx=8)

        ctk.CTkButton(upload_frame, text="Subir archivo", command=self.handle_upload_file).grid(
            row=2, column=1, sticky="e", pady=10
        )

        list_frame = ctk.CTkFrame(tab)
        list_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        list_frame.columnconfigure(1, weight=1)
        list_frame.rowconfigure(0, weight=1)

        ctk.CTkLabel(list_frame, text="Archivos disponibles").grid(row=0, column=0, sticky="nw", pady=10, padx=10)
        self.files_listbox = ctk.CTkScrollableFrame(list_frame, height=180)
        self.files_listbox.grid(row=0, column=1, sticky="nsew", pady=10, padx=10)

        self.download_box = ctk.CTkTextbox(list_frame, height=160)
        self.download_box.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        self.download_box.insert("1.0", "Selecciona un archivo para simular la descarga (descifrado).")
        self.download_box.configure(state="disabled")

        self.refresh_files()

    # --- Manejadores de eventos ---
    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        success, message, usuario = iniciar_sesion(username, password)
        if success and usuario:
            self.current_user = usuario
            self.status_label.configure(text=message, text_color="green")
            self.render_dashboard()
        else:
            self.status_label.configure(text=message, text_color="red")
            messagebox.showerror("Autorización Fallida", message)

    def handle_register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        success, message = registrar_usuario(username, password)

        if success:
            self.status_label.configure(text=message, text_color="green")
            messagebox.showinfo("Registro Exitoso", message)
            self.username_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
        else:
            self.status_label.configure(text=message, text_color="red")
            messagebox.showerror("Fallo de Registro", message)

    def handle_generate_keys(self):
        if not self.current_user:
            return
        pair = generate_rsa_keypair(self.current_user)
        self._render_keys(pair)
        messagebox.showinfo(
            "Llaves generadas",
            "Se creó un nuevo par de llaves RSA para firmar y compartir código de forma segura.",
        )

    def handle_change_password(self):
        if not self.current_user:
            return
        old = self.old_password_entry.get()
        new = self.new_password_entry.get()

        success, msg = change_password(self.current_user, old, new)
        color = "green" if success else "red"
        self.password_status.configure(text=msg, text_color=color)
        if success:
            self.old_password_entry.delete(0, "end")
            self.new_password_entry.delete(0, "end")
            messagebox.showinfo("Contraseña actualizada", msg)
        else:
            messagebox.showerror("No se pudo actualizar", msg)

    def handle_upload_file(self):
        if not self.current_user:
            return
        nombre = self.file_name_entry.get()
        contenido = self.file_content_box.get("1.0", "end").strip()
        if not contenido:
            messagebox.showwarning("Contenido vacío", "Agrega el contenido del archivo para subirlo.")
            return

        nuevo = store_code_file(self.current_user, nombre, contenido)
        self.file_content_box.delete("1.0", "end")
        self.file_name_entry.delete(0, "end")
        self.refresh_files()
        messagebox.showinfo(
            "Archivo guardado",
            f"El archivo '{nuevo.nombre_archivo}' se almacenó cifrado y quedó asociado al usuario.",
        )

    def refresh_files(self):
        for widget in self.files_listbox.winfo_children():
            widget.destroy()

        for code_file in listar_archivos():
            frame = ctk.CTkFrame(self.files_listbox)
            frame.pack(fill="x", padx=4, pady=4)
            ctk.CTkLabel(frame, text=f"#{code_file.id} · {code_file.nombre_archivo}").pack(side="left", padx=6, pady=6)
            ctk.CTkButton(
                frame,
                text="Descargar",
                width=100,
                command=lambda fid=code_file.id: self.handle_download_file(fid),
            ).pack(side="right", padx=6, pady=6)

    def handle_download_file(self, file_id: int):
        code_file = obtener_archivo_por_id(file_id)
        if not code_file:
            return
        self.download_box.configure(state="normal")
        self.download_box.delete("1.0", "end")
        self.download_box.insert(
            "1.0",
            f"Archivo: {code_file.nombre_archivo}\n"
            f"Propietario: usuario {code_file.propietario_id}\n\n"
            f"Contenido (descifrado):\n{code_file.contenido}",
        )
        self.download_box.configure(state="disabled")


if __name__ == "__main__":
    app = AuthApp()
    app.mainloop()
