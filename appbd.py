from typing import Optional
import customtkinter as ctk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename, asksaveasfilename

from models import KeyPair, User

# ---- STORAGE MySQL ----
from storagebd import (
    authenticate,
    create_user,
    generate_and_store_keys,
    get_keys_for_user,
    list_users,
    update_password,
    user_has_keys,
    get_projects_for_user,
    download_project_file,
    store_project_file,   # debes implementarla en storagebd
)

# ---- CRYPTO MODULES ----
from aes_hybrid import cifrar_archivo_hibrido, descifrar_archivo_hibrido
from rsa_utils import firmar_archivo
from hash_utils import hash_archivo


class SecureApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.current_user: Optional[User] = None

        self.title("ChuchoCripOscar · Seguridad de Código")
        self.geometry("1080x640")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)

        self.login_frame = None
        self.dashboard = None
        self.tabs = None
        self.admin_tab = None

        self.render_login()

    # ================================
    # LOGIN
    # ================================
    def render_login(self) -> None:
        if self.dashboard:
            self.dashboard.destroy()

        self.login_frame = ctk.CTkFrame(self.content, corner_radius=12)
        self.login_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(
            self.login_frame,
            text="Acceso Seguro",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(pady=(22, 6))

        # Usuario
        ctk.CTkLabel(self.login_frame, text="Usuario").pack()
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="ej: lider")
        self.username_entry.pack(fill="x", padx=48, pady=6)

        # Password
        ctk.CTkLabel(self.login_frame, text="Contraseña").pack()
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="••••••", show="*")
        self.password_entry.pack(fill="x", padx=48, pady=6)

        actions = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        actions.pack(pady=14)

        ctk.CTkButton(actions, text="Iniciar sesión", command=self.handle_login).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Registrar", command=self.handle_register).pack(side="left", padx=8)

        self.status_label = ctk.CTkLabel(self.login_frame, text="", text_color="gray")
        self.status_label.pack(pady=6)

    # ================================
    # DASHBOARD
    # ================================
    def render_dashboard(self) -> None:
        if self.login_frame:
            self.login_frame.destroy()

        self.dashboard = ctk.CTkFrame(self.content, corner_radius=12)
        self.dashboard.grid(row=0, column=0, sticky="nsew")

        header = ctk.CTkFrame(self.dashboard, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))
        header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text=f"Panel de seguridad · {self.current_user.username}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(header, text="Cerrar sesión", command=self.handle_logout).grid(row=0, column=1)

        self.tabs = ctk.CTkTabview(self.dashboard)
        self.tabs.grid(row=1, column=0, sticky="nsew")

        self._build_keys_tab()
        self._build_password_tab()
        self._build_files_tab()

        if self.current_user.username == "lider":
            self._build_admin_tab()

    # ================================
    # TAB: LLAVES RSA
    # ================================
    def _build_keys_tab(self) -> None:
        tab = self.tabs.add("Llaves RSA")

        ctk.CTkLabel(
            tab,
            text="Genera y almacena tu llave pública/privada.",
            wraplength=520,
        ).pack(pady=10)

        self.keys_box = ctk.CTkTextbox(tab, height=200)
        self.keys_box.pack(fill="x", padx=18, pady=12)
        self.keys_box.insert("1.0", "Presiona para generar tus llaves RSA.")
        self.keys_box.configure(state="disabled")

        ctk.CTkButton(tab, text="Generar par RSA", command=self.handle_generate_keys).pack(pady=6)

        self.keys_status_label = ctk.CTkLabel(tab, text="")
        self.keys_status_label.pack()

        existing = get_keys_for_user(self.current_user)
        if existing:
            self._render_keys(existing)
            self.keys_status_label.configure(text="Llave pública ya registrada.")

    def _render_keys(self, keypair: KeyPair):
        self.keys_box.configure(state="normal")
        self.keys_box.delete("1.0", "end")
        self.keys_box.insert(
            "1.0",
            f"Llave pública:\n{keypair.public_key}\n\nLlave privada:\n{keypair.private_key}",
        )
        self.keys_box.configure(state="disabled")

    # ================================
    # TAB: CONTRASEÑA
    # ================================
    def _build_password_tab(self) -> None:
        tab = self.tabs.add("Contraseña")
        tab.columnconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Actualiza tu contraseña").grid(row=0, column=0, columnspan=2, padx=18, pady=10)

        ctk.CTkLabel(tab, text="Actual").grid(row=1, column=0, padx=18)
        self.old_pass_entry = ctk.CTkEntry(tab, show="*")
        self.old_pass_entry.grid(row=1, column=1, padx=18, pady=6)

        ctk.CTkLabel(tab, text="Nueva").grid(row=2, column=0, padx=18)
        self.new_pass_entry = ctk.CTkEntry(tab, show="*")
        self.new_pass_entry.grid(row=2, column=1, padx=18, pady=6)

        ctk.CTkButton(tab, text="Guardar", command=self.handle_change_password).grid(row=3, column=1, sticky="e")

        self.pass_status = ctk.CTkLabel(tab, text="")
        self.pass_status.grid(row=4, column=0, columnspan=2, padx=18, pady=8)

    # ================================
    # TAB: ARCHIVOS DE CÓDIGO
    # ================================
    def _build_files_tab(self) -> None:
        tab = self.tabs.add("Archivos")

        frame = ctk.CTkFrame(tab)
        frame.pack(fill="x", padx=18, pady=18)

        ctk.CTkButton(frame, text="Obtener código", command=self.handle_download).pack(side="left", expand=True, padx=10)
        ctk.CTkButton(frame, text="Subir código", command=self.handle_upload_file).pack(side="left", expand=True, padx=10)

    # ================================
    # TAB: ADMIN (solo líder)
    # ================================
    def _build_admin_tab(self) -> None:
        tab = self.tabs.add("Usuarios (líder)")
        tab.columnconfigure(0, weight=1)

        ctk.CTkLabel(tab, text="Estado de llaves RSA").grid(row=0, column=0, padx=18, pady=16)

        scroll = ctk.CTkScrollableFrame(tab, height=260)
        scroll.grid(row=1, column=0, sticky="nsew")

        for user in list_users():
            frame = ctk.CTkFrame(scroll)
            frame.pack(fill="x", padx=6, pady=4)

            ctk.CTkLabel(frame, text=user.username).pack(side="left", padx=8)
            status = "OK" if user_has_keys(user) else "Falta generar"
            ctk.CTkLabel(frame, text=status).pack(side="right", padx=8)

    # ================================
    # EVENTOS
    # ================================
    def handle_login(self):
        user = self.username_entry.get()
        pwd = self.password_entry.get()

        ok, msg, user_obj = authenticate(user, pwd)
        if not ok:
            messagebox.showerror("Error", msg)
            return

        self.current_user = user_obj
        self.render_dashboard()

    def handle_register(self):
        user = self.username_entry.get()
        pwd = self.password_entry.get()

        ok, msg, _ = create_user(user, pwd)
        if ok:
            messagebox.showinfo("Registro exitoso", msg)
        else:
            messagebox.showerror("Error", msg)

    def handle_generate_keys(self):
        if not self.current_user:
            return

        keypair = generate_and_store_keys(self.current_user)
        self._render_keys(keypair)
        self.keys_status_label.configure(text="Llaves RSA generadas.")

        self._save_keys_to_file(keypair)

    def _save_keys_to_file(self, keypair):
        suggested = f"llaves_{self.current_user.username}.txt"

        path = asksaveasfilename(defaultextension=".txt", initialfile=suggested)
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write("PAR DE LLAVES RSA\n\n")
            f.write("Pública:\n")
            f.write(keypair.public_key)
            f.write("\n\nPrivada:\n")
            f.write(keypair.private_key)

        messagebox.showinfo("Listo", "Llaves guardadas en tu equipo.")

    def handle_change_password(self):
        old = self.old_pass_entry.get()
        new = self.new_pass_entry.get()

        ok, msg = update_password(self.current_user, old, new)
        if ok:
            messagebox.showinfo("Correcto", msg)
        else:
            messagebox.showerror("Error", msg)

    # ================================
    # SUBIR ARCHIVO
    # ================================
    def handle_upload_file(self):
        if not self.current_user:
            return

        path = askopenfilename()
        if not path:
            return

        keys = get_keys_for_user(self.current_user)
        if not keys:
            messagebox.showerror("Error", "Genera tus llaves RSA primero.")
            return

        enc_path = cifrar_archivo_hibrido(path, keys.public_key)
        hash_archivo(path)
        firmar_archivo(path, keys.private_key)

        store_project_file(self.current_user, path, enc_path)

        messagebox.showinfo("Éxito", f"Código cifrado y guardado.")

    # ================================
    # DESCARGAR ARCHIVO
    # ================================
    def handle_download(self):
        if not self.current_user:
            return

        keys = get_keys_for_user(self.current_user)
        if not keys:
            messagebox.showerror("Error", "No tienes llaves RSA generadas.")
            return

        proyectos = get_projects_for_user(self.current_user)
        if not proyectos:
            messagebox.showerror("Sin proyectos", "No tienes permisos sobre proyectos.")
            return

        nombres = [p["nombre_proyecto"] for p in proyectos]
        idx = self.select_from_list("Selecciona proyecto", nombres)
        if idx is None:
            return

        proyecto = proyectos[idx]
        enc_path = proyecto["ubicacion_codigo_cifrado"]

        dec_path = descifrar_archivo_hibrido(enc_path, keys.private_key)

        messagebox.showinfo("Descifrado", f"Archivo listo en:\n{dec_path}")

    # ================================
    # SELECCIÓN DE LISTA
    # ================================
    def select_from_list(self, title, items):
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("420x200")

        var = ctk.StringVar(value=items[0])
        combo = ctk.CTkComboBox(win, values=items, variable=var)
        combo.pack(pady=20)

        result = {"value": None}

        def choose():
            result["value"] = items.index(var.get())
            win.destroy()

        ctk.CTkButton(win, text="Seleccionar", command=choose).pack(pady=10)

        win.grab_set()
        win.wait_window()
        return result["value"]

    def handle_logout(self):
        self.current_user = None
        self.render_login()


if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()
