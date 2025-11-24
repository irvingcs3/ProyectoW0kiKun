
from typing import Optional
import customtkinter as ctk
from tkinter import messagebox
from models import CodeFile, KeyPair, User
from storage import (
    authenticate,
    create_user,
    generate_and_store_keys,
    get_keys_for_user,
    list_users,
    seed_demo_user,
    update_password,
    user_has_keys,
)
from aes_hybrid import cifrar_archivo_hibrido, descifrar_archivo_hibrido
from rsa_utils import firmar_archivo, verificar_firma
from hash_utils import hash_archivo
from storage import store_code_file, get_keys_for_user
from tkinter.filedialog import askopenfilename, asksaveasfilename

class SecureApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.current_user: Optional[User] = None

        seed_demo_user()  

        self.title(" ChuchoCripOscar")
        self.geometry("1080x640")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        self.content.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)

        self.login_frame: Optional[ctk.CTkFrame] = None
        self.dashboard: Optional[ctk.CTkFrame] = None
        self.tabs: Optional[ctk.CTkTabview] = None
        self.admin_tab: Optional[ctk.CTkFrame] = None

        self.render_login()

    def render_login(self) -> None:
        if self.dashboard:
            self.dashboard.destroy()
        if self.login_frame:
            self.login_frame.destroy()

        self.login_frame = ctk.CTkFrame(self.content, corner_radius=12)
        self.login_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.login_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.login_frame,
            text="Acceso Seguro",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(pady=(22, 6))

        ctk.CTkLabel(self.login_frame, text="Usuario").pack(pady=(6, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="ej: lider")
        self.username_entry.pack(fill="x", padx=48, pady=6)

        ctk.CTkLabel(self.login_frame, text="Contraseña").pack(pady=(6, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="••••••", show="*")
        self.password_entry.pack(fill="x", padx=48, pady=6)

        actions = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        actions.pack(pady=14)
        ctk.CTkButton(actions, text="Iniciar sesión", width=150, command=self.handle_login).pack(
            side="left", padx=8
        )
        ctk.CTkButton(
            actions,
            text="Registrar",
            width=150,
            fg_color="#3B8ED0",
            hover_color="#2E6EA5",
            command=self.handle_register,
        ).pack(side="left", padx=8)

        self.status_label = ctk.CTkLabel(self.login_frame, text="", text_color="gray")
        self.status_label.pack(pady=(8, 18))

    def render_dashboard(self) -> None:
        if self.login_frame:
            self.login_frame.destroy()
        if self.dashboard:
            self.dashboard.destroy()

        self.dashboard = ctk.CTkFrame(self.content, corner_radius=12)
        self.dashboard.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.dashboard.rowconfigure(1, weight=1)
        self.dashboard.columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            self.dashboard,
            text=f"Panel de seguridad · {self.current_user.username}",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w",
        )
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))

        self.tabs = ctk.CTkTabview(self.dashboard)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.admin_tab = None

        self._build_keys_tab()
        self._build_password_tab()
        self._build_files_tab()
        if self.current_user and self.current_user.username == "lider":
            self._build_admin_tab()
    def _build_keys_tab(self) -> None:
        tab = self.tabs.add("Llaves RSA")
        tab.columnconfigure(0, weight=1)
        ctk.CTkLabel(
            tab,
            text="Genera y almacena tu llave pública/privada. Lista para guardarse en DB.",
            wraplength=520,
            justify="left",
        ).pack(pady=(18, 10), padx=18)
        self.keys_box = ctk.CTkTextbox(tab, height=200)
        self.keys_box.insert("1.0", "Presiona el botón para generar tu par RSA.")
        self.keys_box.configure(state="disabled")
        self.keys_box.pack(fill="x", padx=18, pady=12)
        ctk.CTkButton(tab, text="Generar par RSA", command=self.handle_generate_keys).pack(pady=8)
        self.keys_status_label = ctk.CTkLabel(
            tab,
            text="",
            text_color="#2FA572",
            font=ctk.CTkFont(weight="bold"),
        )
        self.keys_status_label.pack(pady=(0, 12))
        existing = get_keys_for_user(self.current_user) if self.current_user else None
        if existing:
            self._render_keys(existing)
            self.keys_status_label.configure(
                text="Llave pública ya almacenada en la base de datos (simulada)."
            )
    def _render_keys(self, keypair: KeyPair) -> None:
        self.keys_box.configure(state="normal")
        self.keys_box.delete("1.0", "end")
        self.keys_box.insert(
            "1.0",
            f"Llave pública:\n{keypair.public_key}\n\n"
            f"Llave privada (mantener en secreto):\n{keypair.private_key}",
        )
        self.keys_box.configure(state="disabled")

    def _build_password_tab(self) -> None:
        tab = self.tabs.add("Contraseña")
        tab.columnconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Actualiza tu contraseña", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 10)
        )

        ctk.CTkLabel(tab, text="Contraseña actual").grid(row=1, column=0, sticky="w", padx=18, pady=6)
        self.old_pass_entry = ctk.CTkEntry(tab, show="*")
        self.old_pass_entry.grid(row=1, column=1, sticky="ew", padx=18, pady=6)

        ctk.CTkLabel(tab, text="Nueva contraseña").grid(row=2, column=0, sticky="w", padx=18, pady=6)
        self.new_pass_entry = ctk.CTkEntry(tab, show="*")
        self.new_pass_entry.grid(row=2, column=1, sticky="ew", padx=18, pady=6)

        ctk.CTkButton(tab, text="Guardar", command=self.handle_change_password).grid(
            row=3, column=1, sticky="e", padx=18, pady=12
        )

        self.pass_status = ctk.CTkLabel(tab, text="", text_color="gray")
        self.pass_status.grid(row=4, column=0, columnspan=2, sticky="w", padx=18, pady=(0, 16))

    def _build_files_tab(self) -> None:
        tab = self.tabs.add("Archivos de código")
        tab.columnconfigure(0, weight=1)

        buttons = ctk.CTkFrame(tab)
        buttons.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        buttons.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            buttons, text="Obtener código", height=60, command=self.handle_download
        ).grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(
            buttons, text="Subir código", height=60, command=self.handle_upload_file
        ).grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    def _build_admin_tab(self) -> None:
        self.admin_tab = self.tabs.add("Usuarios (líder)")
        self.admin_tab.columnconfigure(0, weight=1)
        header = ctk.CTkLabel(
            self.admin_tab,
            text="Panel de monitoreo de llaves",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))
        desc = ctk.CTkLabel(
            self.admin_tab,
            text=(
                "Solo el usuario líder puede ver el estado de generación de llaves de todos los"
                " usuarios registrados (datos locales simulados)."
            ),
            wraplength=520,
            text_color="gray",
            justify="left",
        )
        desc.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 10))

        self.users_list = ctk.CTkScrollableFrame(self.admin_tab, height=260)
        self.users_list.grid(row=2, column=0, sticky="nsew", padx=18, pady=(4, 18))
        self.admin_tab.rowconfigure(2, weight=1)
        self._refresh_admin_users()

    def _refresh_admin_users(self) -> None:
        for widget in self.users_list.winfo_children():
            widget.destroy()

        for user in list_users():
            self._render_user_card(user)

    def _render_user_card(self, user: User) -> None:
        has_keys = user_has_keys(user)
        card = ctk.CTkFrame(self.users_list, corner_radius=12)
        card.pack(fill="x", padx=4, pady=6)
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(
            left, text=user.username, font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            left,
            text=f"ID: {user.id} | Estado: {'activo' if user.active else 'inactivo'}",
            text_color="gray",
        ).pack(anchor="w")

        status_color = "#25A18E" if has_keys else "#D93F3F"
        status_text = "Llaves generadas" if has_keys else "Pendiente de generación"
        badge = ctk.CTkLabel(
            card,
            text=status_text,
            fg_color=status_color,
            text_color="white",
            corner_radius=10,
            padx=12,
            pady=6,
        )
        badge.pack(side="right", padx=12)

    # ---- Event handlers ----
    def handle_login(self) -> None:
        username = self.username_entry.get()
        password = self.password_entry.get()
        ok, message, user = authenticate(username, password)
        if ok and user:
            self.current_user = user
            self.status_label.configure(text=message, text_color="green")
            self.render_dashboard()
        else:
            self.status_label.configure(text=message, text_color="red")
            messagebox.showerror("Acceso denegado", message)

    def handle_register(self) -> None:
        username = self.username_entry.get()
        password = self.password_entry.get()
        ok, message, user = create_user(username, password)
        color = "green" if ok else "red"
        self.status_label.configure(text=message, text_color=color)

        if ok:
            messagebox.showinfo("Registro exitoso", message)
            self.username_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
        else:
            messagebox.showerror("No se pudo registrar", message)

    def handle_generate_keys(self) -> None:
        if not self.current_user:
            return
        keypair = generate_and_store_keys(self.current_user)
        self._render_keys(keypair)
        self.keys_status_label.configure(
            text="Llave pública almacenada en la base de datos (simulada)."
        )
        self._save_keys_to_file(keypair)
        if getattr(self, "admin_tab", None):
            self._refresh_admin_users()

    def _save_keys_to_file(self, keypair: KeyPair) -> None:
        suggested = f"par_rsa_{self.current_user.username}.txt"
        path = asksaveasfilename(
            defaultextension=".txt",
            initialfile=suggested,
            title="Descargar par de llaves",
        )
        if not path:
            messagebox.showinfo(
                "Llaves generadas",
                "Tu par RSA está listo y la llave pública quedó almacenada en la base de datos.",
            )
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write("Par de llaves RSA generado con ChuchoCripOscar\n")
            f.write(f"Usuario: {self.current_user.username}\n\n")
            f.write(f"Llave pública:\n{keypair.public_key}\n\n")
            f.write(f"Llave privada (mantener en secreto):\n{keypair.private_key}\n")

        messagebox.showinfo(
            "Descarga completada",
            "El par se descargó correctamente y la llave pública fue almacenada en la base de datos.",
        )

    def handle_change_password(self) -> None:
        if not self.current_user:
            return
        old = self.old_pass_entry.get()
        new = self.new_pass_entry.get()

        ok, msg = update_password(self.current_user, old, new)
        color = "green" if ok else "red"
        self.pass_status.configure(text=msg, text_color=color)

        if ok:
            self.old_pass_entry.delete(0, "end")
            self.new_pass_entry.delete(0, "end")
            messagebox.showinfo("Contraseña actualizada", msg)
        else:
            messagebox.showerror("No se pudo actualizar", msg)

    def handle_upload_file(self) -> None:
        self.show_pending_feature()


    def refresh_files(self) -> None:
        return

    def show_pending_feature(self) -> None:
        messagebox.showinfo("Próximamente")

    def handle_upload_file(self):
        if not self.current_user:
            return

        path = askopenfilename(title="Selecciona archivo de código")
        if not path:
            return

        keys = get_keys_for_user(self.current_user)
        if not keys:
            messagebox.showerror("Error", "Primero genera tus llaves RSA.")
            return

        enc_path = cifrar_archivo_hibrido(path, keys.public_key)
        hash_archivo(path)
        sig_path = firmar_archivo(path, keys.private_key)

        with open(enc_path, "rb") as f:
            encrypted_content = f.read().hex()

        store_code_file(self.current_user, path, encrypted_content)

        messagebox.showinfo("Cifrado exitoso", f"Archivo cifrado: {enc_path}")


    def handle_download(self):
        keys = get_keys_for_user(self.current_user)
        if not keys:
            messagebox.showerror("Error", "No tienes llaves RSA generadas.")
            return

        path = askopenfilename(title="Selecciona archivo cifrado .enc")
        if not path:
            return

        dec_path = descifrar_archivo_hibrido(path, keys.private_key)
        messagebox.showinfo("Descifrado completo", f"Archivo descifrado: {dec_path}")




if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()
