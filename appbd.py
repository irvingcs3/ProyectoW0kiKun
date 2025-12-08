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
    obtener_proyectos_escritura,
    subir_archivo_hibrido,
    crear_nuevo_proyecto,
    asignar_permiso_proyecto,
    obtener_todos_los_proyectos
)

# ---- CRYPTO MODULES ----
from aes_hybrid import descifrar_con_aes_maestra
from rsa_utils import firmar_archivo
from hash_utils import hash_archivo


class SecureApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.current_user: Optional[User] = None

        self.title("ChuchoCripOscar · Seguridad de Código")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("dark-blue")

        self.primary_bg = "#0b1628"
        self.surface_bg = "#12223e"
        self.accent = "#4fd1c5"

        self.configure(fg_color=self.primary_bg)
        self.geometry("960x620")
        self.resizable(False, False)

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        self._center_window()

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

        for i in range(3):
            self.content.columnconfigure(i, weight=1)
            self.content.rowconfigure(i, weight=1)

        self.login_frame = ctk.CTkFrame(
            self.content, corner_radius=16, fg_color=self.surface_bg, width=880, height=520
        )
        self.login_frame.grid(row=1, column=1, padx=10, pady=10)
        self.login_frame.columnconfigure(0, weight=1)
        self.login_frame.columnconfigure(1, weight=1)

        hero = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        hero.grid(row=0, column=0, sticky="nsew", padx=26, pady=26)
        hero.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hero,
            text="ChuchoCripOscar",
            font=ctk.CTkFont(size=32, weight="bold"),
        ).grid(row=0, column=0, sticky="w", pady=(4, 2))
        ctk.CTkLabel(
            hero,
            text="Control profesional de cifrado y manejo de código",
            font=ctk.CTkFont(size=16),
            text_color="#cfd8e3",
            wraplength=420,
            justify="left",
        ).grid(row=1, column=0, sticky="w")

        form_wrapper = ctk.CTkFrame(self.login_frame, corner_radius=14, fg_color="#1b2f52")
        form_wrapper.grid(row=0, column=1, sticky="nsew", padx=26, pady=26)
        form_wrapper.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form_wrapper,
            text="Acceso",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).grid(row=0, column=0, pady=(12, 6))

        ctk.CTkLabel(form_wrapper, text="Usuario", anchor="w").grid(row=1, column=0, sticky="ew", padx=18)
        self.username_entry = ctk.CTkEntry(form_wrapper, placeholder_text="ej: lider")
        self.username_entry.grid(row=2, column=0, sticky="ew", padx=18, pady=6)

        ctk.CTkLabel(form_wrapper, text="Contraseña", anchor="w").grid(row=3, column=0, sticky="ew", padx=18)
        self.password_entry = ctk.CTkEntry(form_wrapper, placeholder_text="••••••", show="*")
        self.password_entry.grid(row=4, column=0, sticky="ew", padx=18, pady=6)

        actions = ctk.CTkFrame(form_wrapper, fg_color="transparent")
        actions.grid(row=5, column=0, pady=16)

        ctk.CTkButton(
            actions,
            text="Iniciar sesión",
            fg_color=self.accent,
            hover_color="#38b2a6",
            command=self.handle_login,
        ).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Registrar", command=self.handle_register).pack(side="left", padx=8)

        self.status_label = ctk.CTkLabel(form_wrapper, text="", text_color="#9fb3c8")
        self.status_label.grid(row=6, column=0, pady=(4, 10))

    def _center_window(self) -> None:
        self.update_idletasks()
        width = 960
        height = 620
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    # ================================
    # DASHBOARD
    # ================================
    def render_dashboard(self) -> None:
        if self.login_frame:
            self.login_frame.destroy()

        self.dashboard = ctk.CTkFrame(self.content, corner_radius=16, fg_color=self.surface_bg)
        self.dashboard.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.dashboard.rowconfigure(1, weight=1)
        self.dashboard.columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.dashboard, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 10))
        header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text=f"Panel de seguridad · {self.current_user.username}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(header, text="Cerrar sesión", command=self.handle_logout).grid(row=0, column=1)

        self.tabs = ctk.CTkTabview(self.dashboard, segmented_button_selected_color=self.accent)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))

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

        container = ctk.CTkFrame(tab, fg_color="#0f1c32", corner_radius=14)
        container.pack(fill="both", expand=True, padx=16, pady=16)
        container.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            container,
            text="Genera y almacena tu llave pública/privada.",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(
            container,
            text="Protege tus proyectos con criptografía de 2048 bits.",
            text_color="#9fb3c8",
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))

        self.keys_box = ctk.CTkTextbox(container, height=220)
        self.keys_box.grid(row=2, column=0, sticky="ew", padx=16, pady=12)
        self.keys_box.insert("1.0", "Presiona para generar tus llaves RSA.")
        self.keys_box.configure(state="disabled")

        self.generate_keys_btn = ctk.CTkButton(
            container,
            text="Generar par RSA",
            fg_color=self.accent,
            hover_color="#38b2a6",
            command=self.handle_generate_keys,
        )
        self.generate_keys_btn.grid(row=3, column=0, pady=6)

        self.keys_status_label = ctk.CTkLabel(container, text="", text_color="#9fb3c8")
        self.keys_status_label.grid(row=4, column=0, pady=(4, 18))

        existing = get_keys_for_user(self.current_user)
        if existing:
            self._render_keys(existing)
            self.keys_status_label.configure(text="Llave pública ya registrada.")
            self.generate_keys_btn.configure(state="disabled")

    def _render_keys(self, keypair: KeyPair):
        self.keys_box.configure(state="normal")
        self.keys_box.delete("1.0", "end")
        self.keys_box.insert(
            "1.0",
            f"Llave pública:\n{keypair.public_key}\n\nLlave privada (NO SE GUARDA):\nVerifica tu archivo local.\n",
        )
        self.keys_box.configure(state="disabled")

    # ================================
    # TAB: CONTRASEÑA
    # ================================
    def _build_password_tab(self) -> None:
        tab = self.tabs.add("Contraseña")
        tab.columnconfigure(0, weight=1)

        form = ctk.CTkFrame(tab, fg_color="#0f1c32", corner_radius=14)
        form.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        form.columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Actualiza tu contraseña", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, columnspan=2, padx=18, pady=12, sticky="w"
        )

        ctk.CTkLabel(form, text="Actual").grid(row=1, column=0, padx=18, sticky="w")
        self.old_pass_entry = ctk.CTkEntry(form, show="*")
        self.old_pass_entry.grid(row=1, column=1, padx=18, pady=6, sticky="ew")

        ctk.CTkLabel(form, text="Nueva").grid(row=2, column=0, padx=18, sticky="w")
        self.new_pass_entry = ctk.CTkEntry(form, show="*")
        self.new_pass_entry.grid(row=2, column=1, padx=18, pady=6, sticky="ew")

        ctk.CTkButton(
            form,
            text="Guardar",
            fg_color=self.accent,
            hover_color="#38b2a6",
            command=self.handle_change_password,
        ).grid(row=3, column=1, sticky="e", padx=18, pady=(10, 6))

        self.pass_status = ctk.CTkLabel(form, text="", text_color="#9fb3c8")
        self.pass_status.grid(row=4, column=0, columnspan=2, padx=18, pady=(6, 14), sticky="w")

    # ================================
    # TAB: ARCHIVOS
    # ================================
    def _build_files_tab(self) -> None:
        tab = self.tabs.add("Archivos")

        frame = ctk.CTkFrame(tab, fg_color="#0f1c32", corner_radius=14)
        frame.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            frame,
            text="Gestiona los artefactos cifrados de tus proyectos.",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=(14, 6))
        ctk.CTkLabel(frame, text="Descarga o sube código protegido para tu equipo.", text_color="#9fb3c8").pack()

        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.pack(fill="x", pady=20)

        ctk.CTkButton(
            actions,
            text="Obtener código",
            fg_color=self.accent,
            hover_color="#38b2a6",
            command=self.handle_download,
        ).pack(side="left", expand=True, padx=12, pady=4, fill="x")
        ctk.CTkButton(actions, text="Subir código", command=self.handle_upload_file).pack(
            side="left", expand=True, padx=12, pady=4, fill="x"
        )

    # ================================
    # TAB: ADMIN (solo líder)
    # ================================
    def _build_admin_tab(self) -> None:
        tab = self.tabs.add("Admin")
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)

        # SECCIÓN 1: CREAR PROYECTO
        frame_crear = ctk.CTkFrame(tab, fg_color="#0f1c32", corner_radius=12)
        frame_crear.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(frame_crear, text="Crear Nuevo Proyecto", font=ctk.CTkFont(weight="bold")).pack(pady=(10,5))
        self.new_proj_entry = ctk.CTkEntry(frame_crear, placeholder_text="Nombre del Proyecto")
        self.new_proj_entry.pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(frame_crear, text="Crear", fg_color=self.accent, hover_color="#38b2a6", command=self.handle_create_project).pack(pady=10)

        # SECCIÓN 2: ASIGNAR PERMISOS
        frame_permisos = ctk.CTkFrame(tab, fg_color="#0f1c32", corner_radius=12)
        frame_permisos.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(frame_permisos, text="Asignar Permisos", font=ctk.CTkFont(weight="bold")).pack(pady=(10,5))
        
        ctk.CTkButton(frame_permisos, text="Refrescar Listas", command=self.refresh_admin_lists, width=100).pack(pady=5)

        self.combo_proyectos = ctk.CTkComboBox(frame_permisos, values=["Cargar..."])
        self.combo_proyectos.pack(pady=5, padx=10)
        
        self.combo_usuarios = ctk.CTkComboBox(frame_permisos, values=["Cargar..."])
        self.combo_usuarios.pack(pady=5, padx=10)

        self.combo_tipo = ctk.CTkComboBox(frame_permisos, values=["LECTURA", "ESCRITURA"])
        self.combo_tipo.pack(pady=5, padx=10)

        ctk.CTkButton(frame_permisos, text="Asignar", fg_color=self.accent, hover_color="#38b2a6", command=self.handle_assign_permission).pack(pady=10)

        # SECCIÓN 3: LISTA DE USUARIOS (MONITOREO)
        frame_lista = ctk.CTkScrollableFrame(tab, height=200, fg_color="#0f1c32", corner_radius=12)
        frame_lista.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        
        ctk.CTkLabel(frame_lista, text="Estado de Usuarios y Llaves", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=5)

        for user in list_users():
            f = ctk.CTkFrame(frame_lista, fg_color="#132744")
            f.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(f, text=f"ID {user.id} | {user.username}").pack(side="left", padx=10)
            status = "Llaves OK" if user_has_keys(user) else "Sin Llaves"
            ctk.CTkLabel(f, text=status, text_color="gray").pack(side="right", padx=10)

    def refresh_admin_lists(self):
        proyectos = obtener_todos_los_proyectos()
        if proyectos:
            vals = [f"{p['id_proyecto']} - {p['nombre_proyecto']}" for p in proyectos]
            self.combo_proyectos.configure(values=vals)
            self.combo_proyectos.set(vals[0])
        else:
            self.combo_proyectos.configure(values=["Sin proyectos"])

        usuarios = list_users()
        if usuarios:
            vals = [f"{u.id} - {u.username}" for u in usuarios]
            self.combo_usuarios.configure(values=vals)
            self.combo_usuarios.set(vals[0])
        else:
            self.combo_usuarios.configure(values=["Sin usuarios"])

    def handle_create_project(self):
        nombre = self.new_proj_entry.get()
        if not nombre:
            return
        
        ok, msg = crear_nuevo_proyecto(nombre, self.current_user.id)
        if ok:
            messagebox.showinfo("Éxito", msg)
            self.new_proj_entry.delete(0, 'end')
            self.refresh_admin_lists()
        else:
            messagebox.showerror("Error", msg)

    def handle_assign_permission(self):
        proj_str = self.combo_proyectos.get()
        user_str = self.combo_usuarios.get()
        permiso = self.combo_tipo.get()

        if "Sin " in proj_str or "Sin " in user_str:
            return

        id_proj = int(proj_str.split(" - ")[0])
        id_user = int(user_str.split(" - ")[0])

        ok, msg = asignar_permiso_proyecto(id_proj, id_user, permiso)
        if ok:
            messagebox.showinfo("Éxito", msg)
        else:
            messagebox.showerror("Error", msg)


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
        
        if self.current_user.username == "lider":
            self.refresh_admin_lists()

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
    # SUBIR ARCHIVO (Lógica Segura)
    # ================================
    def handle_upload_file(self):
        if not self.current_user:
            return

        proyectos = obtener_proyectos_escritura(self.current_user.id)
        if not proyectos:
            messagebox.showerror("Acceso Denegado", "No tienes permisos de ESCRITURA en ningún proyecto.")
            return

        path_codigo = askopenfilename(title="1. Selecciona el código fuente a subir")
        if not path_codigo: return

        messagebox.showinfo("Seguridad Requerida", "Paso de seguridad: Selecciona tu archivo de Llaves RSA para firmar.")
        path_llave = askopenfilename(title="2. Selecciona tu archivo de Llaves (.txt/.pem)", filetypes=[("Llaves", "*.txt *.pem"), ("Todos", "*.*")])
        if not path_llave: return

        nombres = [f"{p['id_proyecto']} - {p['nombre_proyecto']}" for p in proyectos]
        idx = self.select_from_list("Selecciona Proyecto Destino", nombres)
        if idx is None: return
        
        id_proyecto = proyectos[idx]['id_proyecto']

        ok, msg = subir_archivo_hibrido(
            self.current_user.id, 
            id_proyecto, 
            path_codigo, 
            path_llave
        )

        if ok:
            messagebox.showinfo("Subida Exitosa", msg)
        else:
            messagebox.showerror("Error en Subida", msg)

    # ================================
    # DESCARGAR ARCHIVO (Lógica Segura)
    # ================================
    def handle_download(self):
        if not self.current_user:
            return

        proyectos = get_projects_for_user(self.current_user)
        if not proyectos:
            messagebox.showerror("Sin proyectos", "No tienes permisos sobre proyectos.")
            return

        nombres = [f"{p['id_proyecto']} - {p['nombre_proyecto']}" for p in proyectos]
        idx = self.select_from_list("Selecciona proyecto", nombres)
        if idx is None:
            return

        proyecto = proyectos[idx]
        id_proyecto = proyecto['id_proyecto']
        
        enc_path, clave_maestra = download_project_file(id_proyecto)

        if not enc_path:
            messagebox.showerror("Error", "No hay archivo cifrado para este proyecto.")
            return

        try:
            dec_path = descifrar_con_aes_maestra(enc_path, clave_maestra)
            messagebox.showinfo("Descifrado", f"Archivo listo en:\n{dec_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo descifrar: {e}")

    # ================================
    # SELECCIÓN DE LISTA
    # ================================
    def select_from_list(self, title, items):
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("420x200")
        
        win.transient(self) 
        win.grab_set()

        var = ctk.StringVar(value=items[0])
        combo = ctk.CTkComboBox(win, values=items, variable=var)
        combo.pack(pady=20)

        result = {"value": None}

        def choose():
            result["value"] = items.index(var.get())
            win.destroy()

        ctk.CTkButton(win, text="Seleccionar", command=choose).pack(pady=10)

        self.wait_window(win)
        return result["value"]

    def handle_logout(self):
        self.current_user = None
        self.render_login()


if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()