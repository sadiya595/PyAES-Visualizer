import tkinter as tk
from tkinter import messagebox, font
from aes import AES  # Imports the AES class from your aes.py file

# --- Enhanced Dark Theme Style Configuration ---
BG_COLOR = "#2d2d2d"        # Main background
FRAME_BG = "#3c3f41"      # Background for text boxes
TEXT_COLOR = "#f0f0f0"      # Light text for readability
BUTTON_BG = "#0d6efd"      # A vibrant, professional blue
BUTTON_FG = "#ffffff"       # White text on buttons
BORDER_COLOR = "#555555"    # Subtle border color for text boxes

# --- Font Configuration ---
TITLE_FONT = ("Segoe UI", 16, "bold")
LABEL_FONT = ("Segoe UI", 11)
TEXT_FONT = ("Consolas", 11) # Monospaced font, great for code/hex

# --- AES Configuration ---
KEY = b'my-secret-key-16' # Must be 16 bytes

# --- Global AES Instance ---
try:
    aes_cipher = AES(KEY)
except Exception as e:
    messagebox.showerror("Initialization Error", f"Failed to initialize AES cipher: {e}")
    aes_cipher = None

# --- CORE FUNCTIONS (with UX improvement) ---
def encrypt_text():
    if not aes_cipher:
        messagebox.showerror("Error", "AES Cipher is not initialized.")
        return
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    if not plaintext:
        messagebox.showerror("Error", "Please enter some plaintext.")
        return
    try:
        ciphertext = aes_cipher.encrypt(plaintext)
        ciphertext_hex = ciphertext.hex()
        
        ciphertext_output.config(state='normal')
        ciphertext_output.delete("1.0", tk.END)
        ciphertext_output.insert(tk.END, ciphertext_hex)
        ciphertext_output.config(state='disabled')
        
        decrypted_output.config(state='normal')
        decrypted_output.delete("1.0", tk.END)
        decrypted_output.config(state='disabled')
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred: {e}")

def decrypt_text():
    if not aes_cipher:
        messagebox.showerror("Error", "AES Cipher is not initialized.")
        return
    ciphertext_hex = ciphertext_output.get("1.0", tk.END).strip()
    if not ciphertext_hex:
        messagebox.showerror("Error", "No ciphertext to decrypt.")
        return
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = aes_cipher.decrypt(ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        decrypted_output.config(state='normal')
        decrypted_output.delete("1.0", tk.END)
        decrypted_output.insert(tk.END, decrypted_text)
        decrypted_output.config(state='disabled')
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Could not decrypt message. This usually means the key is wrong or the ciphertext has been altered.")

# --- NEW ENHANCED GUI SETUP ---
root = tk.Tk()
root.title("AES Encryption and Decryption") # CHANGED
root.geometry("600x680") # Increased height slightly for new layout
root.configure(bg=BG_COLOR)
root.resizable(False, False)

main_frame = tk.Frame(root, bg=BG_COLOR, padx=25, pady=20)
main_frame.pack(fill="both", expand=True)

# Title
tk.Label(main_frame, text="AES Encryption and Decryption", font=TITLE_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=(0, 20)) # CHANGED

# 1. Plaintext Input
tk.Label(main_frame, text="Plaintext", font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
plaintext_entry = tk.Text(main_frame, height=5, bg=FRAME_BG, fg=TEXT_COLOR, font=TEXT_FONT, relief="solid", borderwidth=1, highlightthickness=1, highlightbackground=BORDER_COLOR, insertbackground=TEXT_COLOR)
plaintext_entry.pack(pady=(5, 0), fill="x", expand=True)

# Encrypt Button
encrypt_button = tk.Button(main_frame, text="Encrypt", command=encrypt_text, font=LABEL_FONT, bg=BUTTON_BG, fg=BUTTON_FG, relief="flat", padx=20, pady=7, cursor="hand2")
encrypt_button.pack(pady=15)

# 2. Ciphertext Output
tk.Label(main_frame, text="Ciphertext (Hex)", font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
ciphertext_output = tk.Text(main_frame, height=8, bg=FRAME_BG, fg=TEXT_COLOR, font=TEXT_FONT, relief="solid", borderwidth=1, highlightthickness=1, highlightbackground=BORDER_COLOR, state='disabled')
ciphertext_output.pack(pady=(5, 0), fill="x", expand=True)

# Decrypt Button
decrypt_button = tk.Button(main_frame, text="Decrypt", command=decrypt_text, font=LABEL_FONT, bg=BUTTON_BG, fg=BUTTON_FG, relief="flat", padx=20, pady=7, cursor="hand2")
decrypt_button.pack(pady=15) # MOVED

# 3. Decrypted Text Output
tk.Label(main_frame, text="Decrypted Text", font=LABEL_FONT, bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
decrypted_output = tk.Text(main_frame, height=5, bg=FRAME_BG, fg=TEXT_COLOR, font=TEXT_FONT, relief="solid", borderwidth=1, highlightthickness=1, highlightbackground=BORDER_COLOR, state='disabled')
decrypted_output.pack(pady=5, fill="x", expand=True)

root.mainloop()

