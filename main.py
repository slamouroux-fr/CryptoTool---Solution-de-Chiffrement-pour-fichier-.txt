import os
import secrets
import shutil
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- Constants ---
SALT_LEN = 16
IV_LEN = 12
ARGON2_TIME = 2
ARGON2_MEMORY = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32

CREDITS_TEXT = "Sofiane LAMOUROUX - contact@slamouroux.fr"

# --- Crypto Logic ---
def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )

def encrypt_file_logic(filepath: str, password: str, callback=None):
    if not os.path.exists(filepath):
        raise FileNotFoundError("Fichier introuvable.")
    
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    
    salt = secrets.token_bytes(SALT_LEN)
    iv = secrets.token_bytes(IV_LEN)
    key = derive_key(password, salt)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    out_path = filepath + ".enc"
    with open(out_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)
    
    return out_path

def decrypt_file_logic(filepath: str, password: str, callback=None):
    if not os.path.exists(filepath):
        raise FileNotFoundError("Fichier introuvable.")
    
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    if len(file_data) < SALT_LEN + IV_LEN:
        raise ValueError("Fichier corrompu.")
    
    salt = file_data[:SALT_LEN]
    iv = file_data[SALT_LEN:SALT_LEN+IV_LEN]
    ciphertext = file_data[SALT_LEN+IV_LEN:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    
    # Determines output name
    if filepath.endswith(".enc"):
        out_path = filepath[:-4]
    else:
        out_path = filepath + ".decrypted"
    
    with open(out_path, 'wb') as f:
        f.write(plaintext)
        
    return out_path

def encrypt_folder_logic(folderpath: str, password: str, callback=None):
    if not os.path.exists(folderpath):
        raise FileNotFoundError("Dossier introuvable.")
    
    # Make archive
    shutil.make_archive(folderpath, 'zip', folderpath)
    zip_path = folderpath + ".zip"
    
    # Encrypt the zip
    try:
        enc_path = encrypt_file_logic(zip_path, password, callback)
    finally:
        # Cleanup the temporary zip
        if os.path.exists(zip_path):
            os.remove(zip_path)
            
    return enc_path

def decrypt_folder_logic(filepath: str, password: str, callback=None):
    # Decrypt to get the zip back
    decrypted_zip = decrypt_file_logic(filepath, password, callback)
    
    # Extract
    try:
        # Assume it replaces the original .zip
        extract_dir = decrypted_zip 
        if extract_dir.endswith(".zip"):
            extract_dir = extract_dir[:-4]
        
        # Ensure unique directory
        base_extract = extract_dir
        counter = 1
        while os.path.exists(extract_dir):
            extract_dir = f"{base_extract}_{counter}"
            counter += 1
            
        shutil.unpack_archive(decrypted_zip, extract_dir)
    finally:
        if os.path.exists(decrypted_zip):
            os.remove(decrypted_zip)
            
    return extract_dir

# --- GUI ---
class UltimateCryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SecureCrypt Ultimate")
        self.geometry("700x550")
        self.resizable(False, False)
        
        # Grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # 1. Header with branding
        self.header = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.header.grid(row=0, column=0, sticky="ew", pady=(20, 10))
        
        self.title_label = ctk.CTkLabel(self.header, text="SecureCrypt Ultimate", font=ctk.CTkFont(size=28, weight="bold"))
        self.title_label.pack()
        
        self.subtitle_label = ctk.CTkLabel(self.header, text="Protection AES-256-GCM & Argon2id", font=ctk.CTkFont(size=12))
        self.subtitle_label.pack()

        # 2. Main Tab View
        self.tabview = ctk.CTkTabview(self, width=600, height=350)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        
        self.tab_encrypt = self.tabview.add("🔒 Chiffrement")
        self.tab_decrypt = self.tabview.add("🔓 Déchiffrement")
        
        self.setup_encryption_ui()
        self.setup_decryption_ui()

        # 3. Progress Bar (Initially hidden)
        self.progress = ctk.CTkProgressBar(self, width=500, mode="indeterminate")
        self.progress.grid(row=2, column=0, pady=10)
        self.progress.grid_remove() # Hide initially

        # 4. Footer Credits
        self.footer = ctk.CTkLabel(self, text=CREDITS_TEXT, font=ctk.CTkFont(size=11), text_color="gray")
        self.footer.grid(row=3, column=0, pady=(0, 15))

    def setup_encryption_ui(self):
        t = self.tab_encrypt
        
        # Mode Switch (File vs Folder)
        self.enc_mode_var = ctk.StringVar(value="file")
        # FIX: on_value/off_value -> onvalue/offvalue
        self.enc_switch = ctk.CTkSwitch(t, text="Mode Dossier", variable=self.enc_mode_var, onvalue="folder", offvalue="file", command=self.toggle_enc_mode)
        self.enc_switch.pack(pady=10)
        
        # Input Path
        self.enc_path_entry = ctk.CTkEntry(t, placeholder_text="Sélectionner un fichier...", width=400)
        self.enc_path_entry.pack(pady=5)
        
        self.btn_browse_enc = ctk.CTkButton(t, text="Parcourir", command=self.browse_encrypt, width=100)
        self.btn_browse_enc.pack(pady=5)
        
        # Password Area
        self.enc_pwd_entry = ctk.CTkEntry(t, placeholder_text="Mot de passe robuste", show="*", width=300)
        self.enc_pwd_entry.pack(pady=(20, 5))
        
        # Show Password Toggle
        self.show_pwd_var = ctk.BooleanVar(value=False)
        self.chk_show_pwd = ctk.CTkCheckBox(t, text="Afficher le mot de passe", variable=self.show_pwd_var, command=lambda: self.toggle_password(self.enc_pwd_entry, self.show_pwd_var))
        self.chk_show_pwd.pack(pady=5)

        # Strength Indicator
        self.strength_label = ctk.CTkLabel(t, text="", font=ctk.CTkFont(size=11))
        self.strength_label.pack(pady=2)
        self.enc_pwd_entry.bind("<KeyRelease>", self.check_strength)

        # Action
        self.btn_do_encrypt = ctk.CTkButton(t, text="Lancer le Chiffrement", fg_color="#2da44e", hover_color="#2c974b", width=200, height=40, font=ctk.CTkFont(weight="bold"), command=self.start_encryption)
        self.btn_do_encrypt.pack(pady=30)

    def setup_decryption_ui(self):
        t = self.tab_decrypt
        
        # Input Path
        self.dec_path_entry = ctk.CTkEntry(t, placeholder_text="Sélectionner un fichier .enc...", width=400)
        self.dec_path_entry.pack(pady=(40, 5))
        
        self.btn_browse_dec = ctk.CTkButton(t, text="Parcourir", command=self.browse_decrypt, width=100)
        self.btn_browse_dec.pack(pady=5)
        
        # Password
        self.dec_pwd_entry = ctk.CTkEntry(t, placeholder_text="Mot de passe de déchiffrement", show="*", width=300)
        self.dec_pwd_entry.pack(pady=(30, 10))
        
        # Show Password Toggle
        self.show_dec_pwd_var = ctk.BooleanVar(value=False)
        self.chk_show_dec_pwd = ctk.CTkCheckBox(t, text="Afficher le mot de passe", variable=self.show_dec_pwd_var, command=lambda: self.toggle_password(self.dec_pwd_entry, self.show_dec_pwd_var))
        self.chk_show_dec_pwd.pack(pady=5)

        # Action
        self.btn_do_decrypt = ctk.CTkButton(t, text="Lancer le Déchiffrement", fg_color="#cf222e", hover_color="#bd2c00", width=200, height=40, font=ctk.CTkFont(weight="bold"), command=self.start_decryption)
        self.btn_do_decrypt.pack(pady=30)

    # --- Helpers ---
    def toggle_enc_mode(self):
        mode = self.enc_mode_var.get()
        if mode == "folder":
            self.enc_path_entry.configure(placeholder_text="Sélectionner un dossier...")
        else:
            self.enc_path_entry.configure(placeholder_text="Sélectionner un fichier...")

    def browse_encrypt(self):
        if self.enc_mode_var.get() == "folder":
            path = filedialog.askdirectory()
        else:
            path = filedialog.askopenfilename()
        if path:
            self.enc_path_entry.delete(0, "end")
            self.enc_path_entry.insert(0, path)

    def browse_decrypt(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted", "*.enc"), ("All files", "*.*")])
        if path:
            self.dec_path_entry.delete(0, "end")
            self.dec_path_entry.insert(0, path)

    def toggle_password(self, entry, var):
        if var.get():
            entry.configure(show="")
        else:
            entry.configure(show="*")
            
    def check_strength(self, event=None):
        pwd = self.enc_pwd_entry.get()
        l = len(pwd)
        if l == 0:
            self.strength_label.configure(text="", text_color="gray")
        elif l < 8:
            self.strength_label.configure(text="Faible", text_color="red")
        elif l < 12:
            self.strength_label.configure(text="Moyen", text_color="orange")
        else:
            self.strength_label.configure(text="Fort", text_color="green")

    # --- Async Execution ---
    def set_loading(self, loading=True):
        if loading:
            self.progress.grid()
            self.progress.start()
            self.btn_do_encrypt.configure(state="disabled")
            self.btn_do_decrypt.configure(state="disabled")
        else:
            self.progress.stop()
            self.progress.grid_remove()
            self.btn_do_encrypt.configure(state="normal")
            self.btn_do_decrypt.configure(state="normal")

    def start_encryption(self):
        path = self.enc_path_entry.get()
        pwd = self.enc_pwd_entry.get()
        mode = self.enc_mode_var.get()
        
        if not path or not pwd:
            messagebox.showwarning("Attention", "Veuillez remplir tous les champs.")
            return

        self.set_loading(True)
        threading.Thread(target=self._run_encryption_thread, args=(path, pwd, mode), daemon=True).start()

    def _run_encryption_thread(self, path, pwd, mode):
        try:
            if mode == "folder":
                out = encrypt_folder_logic(path, pwd)
                msg = f"Dossier chiffré créé :\n{os.path.basename(out)}"
            else:
                out = encrypt_file_logic(path, pwd)
                msg = f"Fichier chiffré créé :\n{os.path.basename(out)}"
            
            self.after(0, lambda: messagebox.showinfo("Succès", msg))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Erreur", str(e)))
        finally:
            self.after(0, lambda: self.set_loading(False))

    def start_decryption(self):
        path = self.dec_path_entry.get()
        pwd = self.dec_pwd_entry.get()
        
        if not path or not pwd:
            messagebox.showwarning("Attention", "Veuillez remplir tous les champs.")
            return
            
        self.set_loading(True)
        threading.Thread(target=self._run_decryption_thread, args=(path, pwd), daemon=True).start()

    def _run_decryption_thread(self, path, pwd):
        try:
            # We don't know if it was a folder or file originally, but logic handles unzip if it was a zip
            # Basic logic: decrypt file. If the internal file is a zip (which we handled in folder logic by naming it .zip.enc), we could auto-unzip.
            # However, my simple folder logic zips THEN encrypts. So decrypting results in 'name.zip'.
            # I should inspect the decrypted filename in the logic to decide whether to unzip.
            
            # Actually, let's reuse the decrypt folder logic if the user THINKS it's a folder? 
            # Or better: Standard decrypt logic restores the file. If it ends in .zip, we propose to unzip or unzip automatically.
            
            # In my logic above `encrypt_folder_logic` produces `folder.zip.enc`.
            # `decrypt_file_logic` on `folder.zip.enc` produces `folder.zip`.
            
            # Let's try to detect if it's a zip by extension after decryption?
            # Or simply try to unzip if `is_zipfile`.
            
            decrypted_path = decrypt_file_logic(path, pwd)
            
            # Auto-detect zip
            import zipfile
            final_msg = f"Fichier restauré :\n{os.path.basename(decrypted_path)}"
            
            if zipfile.is_zipfile(decrypted_path):
                 # It's a folder archive!
                 extract_dir = decrypted_path
                 if extract_dir.endswith(".zip"):
                     extract_dir = extract_dir[:-4]
                 try:
                     shutil.unpack_archive(decrypted_path, extract_dir)
                     os.remove(decrypted_path) # cleanup zip
                     final_msg = f"Dossier restauré :\n{os.path.basename(extract_dir)}"
                 except:
                     pass # Failed to unzip, just keep the zip
            
            self.after(0, lambda: messagebox.showinfo("Succès", final_msg))
            
        except Exception as e:
            msg = str(e)
            if "decryption failed" in msg.lower() or list(e.args) == []:
                 msg = "Mot de passe incorrect ou données corrompues."
            self.after(0, lambda: messagebox.showerror("Erreur", msg))
        finally:
            self.after(0, lambda: self.set_loading(False))

if __name__ == "__main__":
    app = UltimateCryptoApp()
    app.mainloop()
