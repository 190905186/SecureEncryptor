import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, simpledialog, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import datetime  

AUTO_CLEAR_DELAY = 60_000  # 60 seconds

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

LOG_DIR = "logs"   
LOG_FILE = os.path.join(LOG_DIR, "history.log")
os.makedirs(LOG_DIR, exist_ok=True)  # STAGE 7

def password_to_key(password: str, salt: bytes = b'static_salt_here'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message.encode()).decode()

class EncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        root.title("🔐 Secure Encryptor")
        root.geometry("1000x600")
        root.resizable(False, False)

        self.dark_mode = tk.BooleanVar(value=False)

        top_frame = tk.Frame(root)
        top_frame.pack(fill=tk.X, pady=5)
        self.dark_toggle = tk.Checkbutton(top_frame, text="🌙 Dark Mode", variable=self.dark_mode, command=self.toggle_theme)
        self.dark_toggle.pack(side=tk.LEFT, padx=10)
        tk.Button(top_frame, text="📜 View Log", command=self.view_history_log).pack(side=tk.RIGHT, padx=10)

        main_frame = tk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.left_frame = tk.Frame(main_frame, width=300)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)

        self.right_frame = tk.Frame(main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.mode = tk.StringVar(value="password")
        tk.Label(self.left_frame, text="Select Encryption Mode:").pack(anchor='w')
        self.radio_password = tk.Radiobutton(self.left_frame, text="Use Password", variable=self.mode, value="password", command=self.toggle_mode)
        self.radio_keyfile = tk.Radiobutton(self.left_frame, text="Use Saved Key", variable=self.mode, value="keyfile", command=self.toggle_mode)
        self.radio_password.pack(anchor='w')
        self.radio_keyfile.pack(anchor='w')

        self.password_frame = tk.Frame(self.left_frame)
        self.password_entry = tk.Entry(self.password_frame, show="*", width=30)
        tk.Label(self.password_frame, text="Enter Password:").pack(anchor='w')
        self.password_entry.pack(fill=tk.X)
        self.password_frame.pack(fill=tk.X, pady=5)

        self.key_frame = tk.Frame(self.left_frame)
        tk.Label(self.key_frame, text="Select Saved Key:").pack(anchor='w')
        self.key_combo = ttk.Combobox(self.key_frame, values=self.get_key_files(), state="readonly", width=30)
        self.key_combo.pack(fill=tk.X)
        tk.Button(self.key_frame, text="Create New Key", command=self.create_key).pack(pady=5)

        tk.Button(self.left_frame, text="🔒 Encrypt File", command=self.encrypt_file).pack(pady=5, fill=tk.X)
        tk.Button(self.left_frame, text="🔓 Decrypt File", command=self.decrypt_file).pack(pady=5, fill=tk.X)

        tk.Label(self.right_frame, text="Plain Text:").pack(anchor='w')
        self.plain_text = scrolledtext.ScrolledText(self.right_frame, height=5)
        self.plain_text.pack(fill=tk.X, pady=5)
        tk.Button(self.right_frame, text="📂 Load Plain Text from File", command=self.load_plain_text_from_file).pack(pady=2)
        tk.Button(self.right_frame, text="Encrypt", command=self.encrypt).pack(pady=5)

        tk.Label(self.right_frame, text="Encrypted Message:").pack(anchor='w')
        self.encrypted_text = scrolledtext.ScrolledText(self.right_frame, height=5)
        self.encrypted_text.pack(fill=tk.X, pady=5)

        enc_btns = tk.Frame(self.right_frame)
        tk.Button(enc_btns, text="💾 Save", command=self.save_encrypted_to_file).pack(side=tk.LEFT, padx=5)
        tk.Button(enc_btns, text="📂 Load", command=self.load_encrypted_from_file).pack(side=tk.LEFT, padx=5)
        tk.Button(enc_btns, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.encrypted_text)).pack(side=tk.LEFT, padx=5)
        enc_btns.pack(pady=2)

        tk.Button(self.right_frame, text="Decrypt", command=self.decrypt).pack(pady=5)
        tk.Label(self.right_frame, text="Decrypted Message:").pack(anchor='w')
        self.decrypted_text = scrolledtext.ScrolledText(self.right_frame, height=5)
        self.decrypted_text.pack(fill=tk.X, pady=5)

        dec_btns = tk.Frame(self.right_frame)
        tk.Button(dec_btns, text="💾 Save", command=self.save_decrypted_to_file).pack(side=tk.LEFT, padx=5)
        tk.Button(dec_btns, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.decrypted_text)).pack(side=tk.LEFT, padx=5)
        dec_btns.pack(pady=2)

        self.clear_timer = None
        self.toggle_mode()
        self.toggle_theme()


    def toggle_mode(self):
        if self.mode.get() == "password":
            self.key_frame.pack_forget()
            self.password_frame.pack()
        else:
            self.password_frame.pack_forget()
            self.key_combo["values"] = self.get_key_files()
            if self.key_combo["values"]:
                self.key_combo.current(0)
            self.key_frame.pack()

    def log_action(self, action_type, success, input_data=""):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mode = self.mode.get()
        status = "✅ Success" if success else "❌ Failed"
        preview = input_data[:50].replace("\n", " ") + ("..." if len(input_data) > 50 else "")
        log_entry = f"[{timestamp}] [{mode.upper()}] [{action_type.upper()}] {status}: {preview}\n"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)

    def view_history_log(self):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        except:
            content = "(No history found.)"

        win = tk.Toplevel(self.root)
        win.title("📜 Action History Log")
        win.geometry("700x400")
        log_box = scrolledtext.ScrolledText(win, wrap=tk.WORD, state=tk.NORMAL)
        log_box.insert(tk.END, content)
        log_box.configure(state=tk.DISABLED)
        log_box.pack(expand=True, fill="both")

    def get_selected_key(self):
        if self.mode.get() == "password":
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password.")
                return None
            return password_to_key(password)
        else:
            key_name = self.key_combo.get()
            if not key_name:
                messagebox.showerror("Error", "Please select a key.")
                return None
            try:
                with open(os.path.join(KEY_DIR, key_name), "rb") as f:
                    return f.read()
            except:
                messagebox.showerror("Error", "Failed to load selected key.")
                return None

    def encrypt(self):
        key = self.get_selected_key()
        if not key:
            return
        message = self.plain_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to encrypt.")
            return
        try:
            encrypted = encrypt_message(message, key)
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, encrypted)
            self.schedule_auto_clear()
            self.log_action("encrypt", True, message)  # ✅ log
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log_action("encrypt", False, message)  # ❌ log

    def decrypt(self):
        key = self.get_selected_key()
        if not key:
            return
        encrypted_message = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showwarning("Warning", "Please enter encrypted text.")
            return
        try:
            decrypted = decrypt_message(encrypted_message, key)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted)
            self.schedule_auto_clear()
            self.log_action("decrypt", True, encrypted_message)  # ✅ log
        except Exception as e:
            messagebox.showerror("Decryption Failed", f"Reason: {e}")
            self.log_action("decrypt", False, encrypted_message)  # ❌ log

    def encrypt_file(self):
        key = self.get_selected_key()
        if not key:
            return
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            encrypted = Fernet(key).encrypt(data)
            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                    filetypes=[("Encrypted files", "*.enc")])
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(encrypted)
                messagebox.showinfo("Success", f"File saved:\n{save_path}")
                self.log_action("encrypt_file", True, os.path.basename(file_path))  # ✅ log
        except Exception as e:
            messagebox.showerror("File Error", str(e))
            self.log_action("encrypt_file", False, os.path.basename(file_path))  # ❌ log
              
    def decrypt_file(self):
        key = self.get_selected_key()
        if not key:
            return
        file_path = filedialog.askopenfilename(title="Select encrypted file")
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            decrypted = Fernet(key).decrypt(data)
            save_path = filedialog.asksaveasfilename(title="Save decrypted file")
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(decrypted)
                messagebox.showinfo("Success", f"File decrypted:\n{save_path}")
                self.log_action("decrypt_file", True, os.path.basename(file_path))  # ✅ log
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))
            self.log_action("decrypt_file", False, os.path.basename(file_path))  # ❌ log

    def load_plain_text_from_file(self):
        path = filedialog.askopenfilename(title="Load Plain Text Message",
                                          filetypes=[("Text files", "*.txt"), ("Message files", "*.msg"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.plain_text.delete("1.0", tk.END)
                self.plain_text.insert(tk.END, content)
                messagebox.showinfo("Loaded", "Plain text loaded.")
            except Exception as e:
                messagebox.showerror("Error", f"Load failed: {e}")

    def save_encrypted_to_file(self):
        content = self.encrypted_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".encmsg",
                                            filetypes=[("Encrypted Messages", "*.encmsg")],
                                            title="Save Encrypted Message")
        if path:
            try:
                with open(path, "w") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Encrypted message saved:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")

    def save_decrypted_to_file(self):
        content = self.decrypted_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All Files", "*.*")],
                                            title="Save Decrypted Message")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Decrypted message saved:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")

    def load_encrypted_from_file(self):
        path = filedialog.askopenfilename(title="Load Encrypted Message",
                                          filetypes=[("Encrypted Messages", "*.encmsg"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, "r") as f:
                    content = f.read()
                self.encrypted_text.delete("1.0", tk.END)
                self.encrypted_text.insert(tk.END, content)
                messagebox.showinfo("Loaded", "Encrypted message loaded.")
            except Exception as e:
                messagebox.showerror("Error", f"Load failed: {e}")

    def get_key_files(self):
        return [f for f in os.listdir(KEY_DIR) if f.endswith(".key")]

    def create_key(self):
        name = simpledialog.askstring("Create Key", "Enter a name for the new key:")
        if not name:
            return
        file_path = os.path.join(KEY_DIR, f"{name}.key")
        if os.path.exists(file_path):
            messagebox.showerror("Error", "Key already exists.")
            return
        try:
            with open(file_path, "wb") as f:
                f.write(Fernet.generate_key())
            self.key_combo["values"] = self.get_key_files()
            self.key_combo.set(f"{name}.key")
            messagebox.showinfo("Success", f"Key '{name}' created.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_to_clipboard(self, text_widget):
        text = text_widget.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Clipboard", "Copied to clipboard!")

    def schedule_auto_clear(self):
        if self.clear_timer:
            self.root.after_cancel(self.clear_timer)
        self.clear_timer = self.root.after(AUTO_CLEAR_DELAY, self.auto_clear_sensitive_fields)

    def auto_clear_sensitive_fields(self):
        self.password_entry.delete(0, tk.END)
        self.encrypted_text.delete("1.0", tk.END)
        self.decrypted_text.delete("1.0", tk.END)
        self.clear_timer = None

    def toggle_theme(self):
        bg = "#1e1e1e" if self.dark_mode.get() else "#f0f0f0"
        fg = "white" if self.dark_mode.get() else "black"
        insert_bg = "white" if self.dark_mode.get() else "black"
        selectcolor = "#333" if self.dark_mode.get() else "#f0f0f0"
        widgets = [
            self.root, self.left_frame, self.right_frame,
            self.password_frame, self.key_frame, self.plain_text,
            self.encrypted_text, self.decrypted_text
        ]
        for w in widgets:
            w.configure(bg=bg)

        for text_widget in [self.plain_text, self.encrypted_text, self.decrypted_text]:
            try:
                text_widget.configure(bg=bg, fg=fg, insertbackground=insert_bg)
            except:
                pass

        for radio in [self.radio_password, self.radio_keyfile]:
            radio.configure(bg=bg, fg=fg, selectcolor=selectcolor)

        for widget in self.root.winfo_children():
            self._set_widget_theme(widget, bg, fg)

    def _set_widget_theme(self, widget, bg, fg):
        try:
            widget.configure(bg=bg, fg=fg)
        except:
            pass
        for child in widget.winfo_children():
            self._set_widget_theme(child, bg, fg)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptDecryptApp(root)
    root.mainloop()
