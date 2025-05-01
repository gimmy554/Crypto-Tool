import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Cryptodome.Cipher import AES, DES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import hashlib


# ==============================================
# CLASSICAL CIPHERS
# ==============================================
def caesar_cipher(text, shift=3):
    """Shifts each letter in the text by a fixed number"""
    return "".join(
        chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97))
        if c.isalpha() else c for c in text
    )


def vigenere_cipher(text, key="crypto"):
    """Vigenère cipher using a keyword for variable shifting"""
    key = key.lower()
    result, key_idx = "", 0
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shift = ord(key[key_idx % len(key)]) - 97
            result += chr((ord(char) - base + shift) % 26 + base)
            key_idx += 1
        else:
            result += char
    return result


class GimyCryptoTool:
    def __init__(self, window):
        self.window = window
        self.window.title("Gimy Crypto Tool")
        self.window.geometry("700x900")
        self.window.configure(bg="#1e1e2e")

        # Main container frame
        self.main_frame = tk.Frame(window, bg="#1e1e2e")
        self.main_frame.pack(fill="both", expand=True)

        # Create status bar FIRST
        self.status = tk.StringVar(value="Ready to go!")
        ttk.Label(self.main_frame, textvariable=self.status,
                  background="#27272a", foreground="#a1a1aa",
                  padding=5, relief="sunken").pack(side="bottom", fill="x")

        # Create menu buttons
        self.create_menu_buttons()

        # Container for all pages
        self.pages = {}
        self.current_page = None

        # Create all pages
        self.create_symmetric_page()
        self.create_asymmetric_page()
        self.create_classical_page()
        self.create_hashing_page()
        self.create_signature_page()

        # Show default page AFTER status is initialized
        self.show_page("Symmetric")

    def create_menu_buttons(self):
        """Create navigation buttons on the left side"""
        menu_frame = tk.Frame(self.main_frame, bg="#2a2a3a", width=150)
        menu_frame.pack(side="left", fill="y")
        menu_frame.pack_propagate(False)

        buttons = [
            ("Symmetric", lambda: self.show_page("Symmetric")),
            ("Asymmetric", lambda: self.show_page("Asymmetric")),
            ("Classical", lambda: self.show_page("Classical")),
            ("Hashing", lambda: self.show_page("Hashing")),
            ("Digital Signature", lambda: self.show_page("Digital Signature")),
            ("Help", self.show_help)  # Added Help button
        ]

        for text, command in buttons:
            btn = tk.Button(menu_frame, text=text, command=command,
                            bg="#3b3f48", fg="white", bd=0, padx=20, pady=10,
                            width=15, anchor="w")
            btn.pack(fill="x", pady=2)

    def show_page(self, page_name):
        """Show the selected page and hide others"""
        if self.current_page:
            self.current_page.pack_forget()

        self.current_page = self.pages[page_name]
        self.current_page.pack(side="right", fill="both", expand=True)
        self.status.set(f"{page_name} page loaded")

    def show_help(self):
        """Show a help window with instructions for using the tool"""
        help_window = tk.Toplevel(self.window)
        help_window.title("Gimy Crypto Tool - Help")
        help_window.geometry("600x500")
        help_window.configure(bg="#1e1e2e")

        # Create a scrollable text area for help content
        help_frame = tk.Frame(help_window, bg="#1e1e2e")
        help_frame.pack(fill="both", expand=True, padx=10, pady=10)

        help_text = tk.Text(help_frame, bg="#2a2a3a", fg="white", wrap="word", height=25)
        help_text.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(help_frame, orient="vertical", command=help_text.yview)
        scrollbar.pack(side="right", fill="y")
        help_text.config(yscrollcommand=scrollbar.set)

        # Help content
        help_content = """
        Welcome to Gimy Crypto Tool Help!
        This tool provides various cryptographic functions. Below is a guide to each tab:

        1. Symmetric Encryption (AES/DES)
        - Purpose: Encrypt or decrypt messages using symmetric algorithms (AES or DES).
        - How to Use:
          * Enter your message in the input area or load it from a file.
          * Generate a key using the "Generate Key" button or input your own (base64-encoded).
          * Select an operation: AES Encrypt, AES Decrypt, DES Encrypt, or DES Decrypt.
          * Click "Execute" to process the message.
          * View the result in the output area and save it if needed.
        - Tip: Ensure the key length matches the algorithm (16/24/32 bytes for AES, 8 bytes for DES).

        2. Asymmetric Encryption (RSA)
        - Purpose: Encrypt or decrypt messages using RSA (public/private key pair).
        - How to Use:
          * Enter your message in the input area.
          * Generate a key pair using the "Generate Keys" button.
          * Select "RSA Encrypt" (uses public key) or "RSA Decrypt" (uses private key).
          * Click "Execute" to process the message.
          * The result will appear in the output area.
        - Tip: RSA is suitable for small messages due to its size limitations.

        3. Classical Ciphers
        - Purpose: Apply classical ciphers (Caesar or Vigenère) to text.
        - How to Use:
          * Enter your message in the input area.
          * Select either "Caesar Cipher" (fixed shift) or "Vigenère Cipher" (keyword-based).
          * Click "Execute" to apply the cipher.
          * View the result in the output area.
        - Tip: These ciphers are not secure for modern use but are useful for educational purposes.

        4. Hashing Algorithms
        - Purpose: Generate hashes of messages using MD5, SHA-1, SHA-256, or SHA-512.
        - How to Use:
          * Enter your message in the input area.
          * Select a hashing algorithm from the dropdown.
          * Click "Hash It!" to generate the hash.
          * The hash will appear in the output area.
        - Tip: Use SHA-256 or SHA-512 for better security; MD5 and SHA-1 are considered weak.

        5. Digital Signature
        - Purpose: Sign messages or verify signatures using RSA.
        - How to Use:
          * Enter your message in the input area.
          * Generate a key pair using the "Generate Keys" button.
          * To Sign: Select "Sign," click "Execute," and the signature will appear in the output.
          * To Verify: Paste the signature in the "Signature (for verification)" area, select "Verify," and click "Execute."
          * The result will indicate if the signature is valid.
        - Tip: Keep your private key secure, as it’s used for signing.

        General Tips:
        - Use the "Load File" button to import messages from text files.
        - Use the "Save Result" button to export results to a file.
        - Check the status bar at the bottom for feedback on operations.
        """
        help_text.insert(tk.END, help_content)
        help_text.config(state="disabled")  # Make the text read-only

        # Close button
        tk.Button(help_window, text="Close", command=help_window.destroy,
                  bg="#3b3f48", fg="white").pack(pady=10)

        self.status.set("Help window opened")

    # ==============================================
    # Page Creation Methods
    # ==============================================
    def create_symmetric_page(self):
        """Symmetric encryption page (AES/DES)"""
        frame = tk.Frame(self.main_frame, bg="#1e1e2e")
        self.pages["Symmetric"] = frame

        # Title
        tk.Label(frame, text="Symmetric Encryption", font=("Arial", 18),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=10)

        # Input area
        input_frame = self.create_input_frame(frame, "Message")
        self.symmetric_input = input_frame["input"]

        # Key management
        key_frame = tk.LabelFrame(frame, text="Key", bg="#1e1e2e", fg="white")
        key_frame.pack(fill="x", padx=10, pady=5)

        self.symmetric_key = tk.Entry(key_frame, width=50)
        self.symmetric_key.pack(side="left", padx=5, pady=5)

        tk.Button(key_frame, text="Generate Key", command=self.generate_symmetric_key,
                  bg="#3b3f48", fg="white").pack(side="right", padx=5)

        # Operation selection
        option_frame = tk.Frame(frame, bg="#1e1e2e")
        option_frame.pack(pady=10)

        self.symmetric_option = tk.StringVar(value="AES Encrypt")
        options = ["AES Encrypt", "AES Decrypt", "DES Encrypt", "DES Decrypt"]
        tk.OptionMenu(option_frame, self.symmetric_option, *options).pack()

        # Action button
        tk.Button(frame, text="Execute", command=self.run_symmetric,
                  bg="#4CAF50", fg="white").pack(pady=10)

        # Output area
        output_frame = self.create_output_frame(frame)
        self.symmetric_output = output_frame["output"]

    def create_asymmetric_page(self):
        """Asymmetric encryption page (RSA)"""
        frame = tk.Frame(self.main_frame, bg="#1e1e2e")
        self.pages["Asymmetric"] = frame

        # Title
        tk.Label(frame, text="Asymmetric Encryption (RSA)", font=("Arial", 18),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=10)

        # Input area
        input_frame = self.create_input_frame(frame, "Message")
        self.rsa_input = input_frame["input"]

        # Key management
        key_frame = tk.LabelFrame(frame, text="RSA Keys", bg="#1e1e2e", fg="white")
        key_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(key_frame, text="Public Key:", bg="#1e1e2e", fg="white").pack(anchor="w")
        self.rsa_public = tk.Text(key_frame, height=3)
        self.rsa_public.pack(fill="x", padx=5, pady=2)

        tk.Label(key_frame, text="Private Key:", bg="#1e1e2e", fg="white").pack(anchor="w")
        self.rsa_private = tk.Text(key_frame, height=3)
        self.rsa_private.pack(fill="x", padx=5, pady=2)

        tk.Button(key_frame, text="Generate Keys", command=self.generate_rsa_keys,
                  bg="#3b3f48", fg="white").pack(pady=5)

        # Operation selection
        option_frame = tk.Frame(frame, bg="#1e1e2e")
        option_frame.pack(pady=10)

        self.rsa_option = tk.StringVar(value="RSA Encrypt")
        options = ["RSA Encrypt", "RSA Decrypt"]
        tk.OptionMenu(option_frame, self.rsa_option, *options).pack()

        # Action button
        tk.Button(frame, text="Execute", command=self.run_rsa,
                  bg="#4CAF50", fg="white").pack(pady=10)

        # Output area
        output_frame = self.create_output_frame(frame)
        self.rsa_output = output_frame["output"]

    def create_classical_page(self):
        """Classical ciphers page (Caesar, Vigenère)"""
        frame = tk.Frame(self.main_frame, bg="#1e1e2e")
        self.pages["Classical"] = frame

        # Title
        tk.Label(frame, text="Classical Ciphers", font=("Arial", 18),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=10)

        # Input area
        input_frame = self.create_input_frame(frame, "Message")
        self.classical_input = input_frame["input"]

        # Operation selection
        option_frame = tk.Frame(frame, bg="#1e1e2e")
        option_frame.pack(pady=10)

        self.classical_option = tk.StringVar(value="Caesar Cipher")
        options = ["Caesar Cipher", "Vigenère Cipher"]
        tk.OptionMenu(option_frame, self.classical_option, *options).pack()

        # Action button
        tk.Button(frame, text="Execute", command=self.run_classical,
                  bg="#4CAF50", fg="white").pack(pady=10)

        # Output area
        output_frame = self.create_output_frame(frame)
        self.classical_output = output_frame["output"]

    def create_hashing_page(self):
        """Hashing algorithms page"""
        frame = tk.Frame(self.main_frame, bg="#1e1e2e")
        self.pages["Hashing"] = frame

        # Title
        tk.Label(frame, text="Hashing Algorithms", font=("Arial", 18),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=10)

        # Input area
        input_frame = self.create_input_frame(frame, "Message")
        self.hashing_input = input_frame["input"]

        # Operation selection
        option_frame = tk.Frame(frame, bg="#1e1e2e")
        option_frame.pack(pady=10)

        self.hashing_option = tk.StringVar(value="SHA-256")
        options = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        tk.OptionMenu(option_frame, self.hashing_option, *options).pack()

        # Action button
        tk.Button(frame, text="Hash It!", command=self.run_hashing,
                  bg="#4CAF50", fg="white").pack(pady=10)

        # Output area
        output_frame = self.create_output_frame(frame)
        self.hashing_output = output_frame["output"]

    def create_signature_page(self):
        """Digital Signature page"""
        frame = tk.Frame(self.main_frame, bg="#1e1e2e")
        self.pages["Digital Signature"] = frame

        # Title
        tk.Label(frame, text="Digital Signature", font=("Arial", 18),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=10)

        # Input area
        input_frame = self.create_input_frame(frame, "Message")
        self.signature_input = input_frame["input"]

        # Key management
        key_frame = tk.LabelFrame(frame, text="RSA Keys", bg="#1e1e2e", fg="white")
        key_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(key_frame, text="Public Key:", bg="#1e1e2e", fg="white").pack(anchor="w")
        self.signature_public = tk.Text(key_frame, height=3)
        self.signature_public.pack(fill="x", padx=5, pady=2)

        tk.Label(key_frame, text="Private Key:", bg="#1e1e2e", fg="white").pack(anchor="w")
        self.signature_private = tk.Text(key_frame, height=3)
        self.signature_private.pack(fill="x", padx=5, pady=2)

        tk.Button(key_frame, text="Generate Keys", command=self.generate_rsa_keys,
                  bg="#3b3f48", fg="white").pack(pady=5)

        # Signature input (for verification)
        sig_frame = tk.LabelFrame(frame, text="Signature (for verification)", bg="#1e1e2e", fg="white")
        sig_frame.pack(fill="x", padx=10, pady=5)
        self.signature_sig = tk.Text(sig_frame, height=3)
        self.signature_sig.pack(fill="x", padx=5, pady=5)

        # Operation selection
        option_frame = tk.Frame(frame, bg="#1e1e2e")
        option_frame.pack(pady=10)

        self.signature_option = tk.StringVar(value="Sign")
        options = ["Sign", "Verify"]
        tk.OptionMenu(option_frame, self.signature_option, *options).pack()

        # Action button
        tk.Button(frame, text="Execute", command=self.run_signature,
                  bg="#4CAF50", fg="white").pack(pady=10)

        # Output area
        output_frame = self.create_output_frame(frame)
        self.signature_output = output_frame["output"]

    # ==============================================
    # Helper Methods for Page Creation
    # ==============================================
    def create_input_frame(self, parent, title):
        """Create a standardized input frame"""
        frame = tk.LabelFrame(parent, text=title, bg="#1e1e2e", fg="white")
        frame.pack(fill="x", padx=10, pady=5)

        text = tk.Text(frame, height=5)
        text.pack(fill="x", padx=5, pady=5)

        btn_frame = tk.Frame(frame, bg="#1e1e2e")
        btn_frame.pack(fill="x")

        tk.Button(btn_frame, text="Load File", command=lambda: self.load_file(text),
                  bg="#3b3f48", fg="white").pack(side="left", padx=5)
        tk.Button(btn_frame, text="Clear", command=lambda: text.delete("1.0", tk.END),
                  bg="#3b3f48", fg="white").pack(side="left", padx=5)

        return {"frame": frame, "input": text}

    def create_output_frame(self, parent):
        """Create a standardized output frame"""
        frame = tk.LabelFrame(parent, text="Result", bg="#1e1e2e", fg="white")
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        text = tk.Text(frame, height=7)
        text.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Button(frame, text="Save Result", command=lambda: self.save_output(text),
                  bg="#3b3f48", fg="white").pack(pady=5)

        return {"frame": frame, "output": text}

    # ==============================================
    # Cryptographic Operation Methods
    # ==============================================
    def generate_symmetric_key(self):
        """Generate symmetric key based on selected algorithm"""
        op = self.symmetric_option.get()
        if "AES" in op:
            key = get_random_bytes(16)
            self.status.set("Generated new AES key")
        else:
            key = get_random_bytes(8)
            self.status.set("Generated new DES key")

        self.symmetric_key.delete(0, tk.END)
        self.symmetric_key.insert(0, base64.b64encode(key).decode())

    def generate_rsa_keys(self):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Update both RSA and Signature tabs
        for text_widget in [self.rsa_private, self.signature_private]:
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode())

        for text_widget in [self.rsa_public, self.signature_public]:
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())

        self.status.set("Generated new RSA key pair")

    def run_symmetric(self):
        """Execute symmetric encryption/decryption"""
        message = self.symmetric_input.get("1.0", tk.END).strip()
        op = self.symmetric_option.get()
        key = self.symmetric_key.get()

        try:
            if not key:
                raise ValueError("Key is required!")

            key_bytes = base64.b64decode(key)

            # Validate key lengths
            if "AES" in op and len(key_bytes) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes")
            if "DES" in op and len(key_bytes) != 8:
                raise ValueError("DES key must be 8 bytes")

            # Perform operation
            cipher = (AES if "AES" in op else DES).new(key_bytes, (AES if "AES" in op else DES).MODE_ECB)

            if "Encrypt" in op:
                result = cipher.encrypt(pad(message.encode(), 16 if "AES" in op else 8)).hex()
            else:
                result = unpad(cipher.decrypt(bytes.fromhex(message)), 16 if "AES" in op else 8).decode()

            self.symmetric_output.delete("1.0", tk.END)
            self.symmetric_output.insert("1.0", result)
            self.status.set(f"{op} completed successfully")
        except Exception as e:
            self.symmetric_output.delete("1.0", tk.END)
            self.symmetric_output.insert("1.0", f"Error: {str(e)}")
            self.status.set(f"Error in {op}")

    def run_rsa(self):
        """Execute RSA encryption/decryption"""
        message = self.rsa_input.get("1.0", tk.END).strip()
        op = self.rsa_option.get()

        try:
            if op == "RSA Encrypt":
                pem = self.rsa_public.get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Public key is required!")

                public_key = serialization.load_pem_public_key(pem.encode())
                ciphertext = public_key.encrypt(
                    message.encode(),
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                result = base64.b64encode(ciphertext).decode()
                self.status.set("RSA encryption successful")
            else:
                pem = self.rsa_private.get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Private key is required!")

                private_key = serialization.load_pem_private_key(pem.encode(), None)
                plaintext = private_key.decrypt(
                    base64.b64decode(message),
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
                result = plaintext
                self.status.set("RSA decryption successful")

            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", result)
        except Exception as e:
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", f"Error: {str(e)}")
            self.status.set(f"Error in {op}")

    def run_classical(self):
        """Execute classical cipher operations"""
        message = self.classical_input.get("1.0", tk.END).strip()
        op = self.classical_option.get()

        try:
            if op == "Caesar Cipher":
                result = caesar_cipher(message)
            else:  # Vigenère Cipher
                result = vigenere_cipher(message)

            self.classical_output.delete("1.0", tk.END)
            self.classical_output.insert("1.0", result)
            self.status.set(f"Applied {op} successfully")
        except Exception as e:
            self.classical_output.delete("1.0", tk.END)
            self.classical_output.insert("1.0", f"Error: {str(e)}")
            self.status.set(f"Error in {op}")

    def run_hashing(self):
        """Execute hashing operations"""
        message = self.hashing_input.get("1.0", tk.END).strip()
        op = self.hashing_option.get()

        try:
            if not message:
                raise ValueError("Message is required!")

            hash_func = {
                "MD5": hashlib.md5,
                "SHA-1": hashlib.sha1,
                "SHA-256": hashlib.sha256,
                "SHA-512": hashlib.sha512
            }[op]

            result = hash_func(message.encode()).hexdigest()

            self.hashing_output.delete("1.0", tk.END)
            self.hashing_output.insert("1.0", result)
            self.status.set(f"Created {op} hash successfully")
        except Exception as e:
            self.hashing_output.delete("1.0", tk.END)
            self.hashing_output.insert("1.0", f"Error: {str(e)}")
            self.status.set("Error in hashing")

    def run_signature(self):
        """Execute digital signature operations"""
        message = self.signature_input.get("1.0", tk.END).strip()
        op = self.signature_option.get()

        try:
            if op == "Sign":
                private_pem = self.signature_private.get("1.0", tk.END).strip()
                if not private_pem:
                    raise ValueError("Private key is required!")

                private_key = serialization.load_pem_private_key(
                    private_pem.encode(),
                    password=None
                )

                signature = private_key.sign(
                    message.encode(),
                    rsa_padding.PSS(
                        mgf=rsa_padding.MGF1(hashes.SHA256()),
                        salt_length=rsa_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                result = base64.b64encode(signature).decode()
                self.status.set("Message signed successfully")
            else:  # Verify
                public_pem = self.signature_public.get("1.0", tk.END).strip()
                signature = self.signature_sig.get("1.0", tk.END).strip()

                if not public_pem:
                    raise ValueError("Public key is required!")
                if not signature:
                    raise ValueError("Signature is required!")

                public_key = serialization.load_pem_public_key(public_pem.encode())

                try:
                    public_key.verify(
                        base64.b64decode(signature),
                        message.encode(),
                        rsa_padding.PSS(
                            mgf=rsa_padding.MGF1(hashes.SHA256()),
                            salt_length=rsa_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    result = "Signature is VALID"
                    self.status.set("Signature verified successfully")
                except Exception:
                    result = "Signature is INVALID"
                    self.status.set("Signature verification failed")

            self.signature_output.delete("1.0", tk.END)
            self.signature_output.insert("1.0", result)
        except Exception as e:
            self.signature_output.delete("1.0", tk.END)
            self.signature_output.insert("1.0", f"Error: {str(e)}")
            self.status.set(f"Error in {op}")

    # ==============================================
    # Utility Methods
    # ==============================================
    def load_file(self, text_widget):
        """Load content from file into text widget"""
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as file:
                    text_widget.delete("1.0", tk.END)
                    text_widget.insert(tk.END, file.read())
                self.status.set(f"Loaded {path.split('/')[-1]}")
            except Exception as e:
                messagebox.showerror("Error", f"Couldn't load file: {e}")
                self.status.set(f"Error loading file")

    def save_output(self, text_widget):
        """Save content from text widget to file"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as file:
                    file.write(text_widget.get("1.0", tk.END))
                self.status.set(f"Saved to {path.split('/')[-1]}")
                messagebox.showinfo("Success", "File saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Couldn't save file: {e}")
                self.status.set(f"Error saving file")


if __name__ == "__main__":
    root = tk.Tk()
    app = GimyCryptoTool(root)
    root.mainloop()