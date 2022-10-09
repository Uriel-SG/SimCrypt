import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showerror
import pyperclip
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def menu():
	finestra = tk.Tk()
	finestra.title("SimEncryptor")
	finestra.configure(bg="black")
	finestra.iconbitmap("icosimcrypt.ico")
	frame1 = tk.Frame(finestra, bg="black")
	frame1.pack()
	
	def encryption():
		finestra.destroy()
		
		def refresh():
			window.destroy()
			start_gui()
			
		def start_gui():
			global window
			#Window and frames
			window = tk.Tk()
			window.title("SimEncrypt")
			window.configure(bg="black")
			window.iconbitmap("icosimcrypt.ico")
			frame1 = tk.Frame(window, bg="black")
			frame1.pack()
			frame2 = tk.Frame(window, bg="black")
			frame2.pack()
			
			def encrypt():
				messagetoencrypt = ""
				password = ""
				encryptedmessage = ""
				
				backend = default_backend()
				iterations = 100_000

				def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
					kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(), length=32, salt=salt,
					iterations=iterations, backend=backend)
					return b64e(kdf.derive(password))

				def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
					salt = secrets.token_bytes(16)
					key = _derive_key(password.encode(), salt, iterations)
					return b64e(
						b'%b%b%b' % (
							salt,
							iterations.to_bytes(4, 'big'),
							b64d(Fernet(key).encrypt(message)),
							)
						)

				messagetoencrypt = message.get("1.0", tk.END)
				password = passentry.get()
				encryptedmessage = (password_encrypt(messagetoencrypt.encode(), password))
				encrypted_text["state"] = "normal"
				encrypted_text.insert(tk.END, encryptedmessage)
				
			def exit_encrypt():
				window.destroy()
				menu()
				
			def copy_to_clipboard():
				x = encrypted_text.get("1.0", tk.END)
				pyperclip.copy(x)
		
			#Widgets
			buttons_style = ttk.Style()
			buttons_style.configure('my.TButton', font=('Times', 10))
			buttons_style.configure('big.TButton', font=('Times', 11, 'bold'))
			
			title = tk.Label(frame1, text="Encrypt",
				fg= "white",
				bg= "black",
				font=("Times", 18, "bold"))
			title.pack(fill=tk.X)
			
			message_label = tk.Label(frame1, text="\nWrite here the message to encrypt: ", bg="black", fg="white", font=("Times", 14))
			message_label.pack(fill=tk.X)
			
			message = tk.Text(frame1, padx=15, pady=15, height=7, font=("Times", 14), wrap="word")
			message.pack()
			
			empty = tk.Label(frame1, bg="black").pack(fill=tk.X)	
			
			labelpass = tk.Label(frame1, bg="black", fg="white", text="Password: ", font=("Times", 14)).pack(fill=tk.X)
			
			passentry = tk.Entry(frame1, justify="center", font=("Times", 11))
			passentry.pack()
			
			empty = tk.Label(frame1, bg="black").pack(fill=tk.X)
			
			encryptbutton = ttk.Button(frame1, text="Encrypt", style="big.TButton", command=encrypt)
			encryptbutton.pack()
			
			empty = tk.Label(frame1,bg="black").pack(fill=tk.X)
			
			encrypted_text = tk.Text(frame1, padx=15, pady=15, height=7, font=("Times", 11), wrap="word", state="disabled")
			encrypted_text.pack()
			
			copybutt = ttk.Button(frame1, text="Copy", style="my.TButton", command=copy_to_clipboard)
			copybutt.pack()
			
			empty = tk.Label(frame2, text="\n", bg="black").pack(fill=tk.X)
			
			refreshbutton = ttk.Button(frame2, text="Refresh", style="my.TButton", command=refresh)
			refreshbutton.pack(side=tk.LEFT)
			
			empty = tk.Label(frame2, bg="black").pack(side=tk.LEFT)
			
			exitbutton = ttk.Button(frame2, text="Exit", style="my.TButton", command=exit_encrypt)
			exitbutton.pack(side=tk.LEFT)
		start_gui()
		
	def decryption():
		finestra.destroy()
		
		def refresh():
			window.destroy()
			start_gui()
			
		def start_gui():
			global window
			#Window and frames
			window = tk.Tk()
			window.title("SimEncrypt")
			window.configure(bg="black")
			window.iconbitmap("icosimcrypt.ico")
			frame1 = tk.Frame(window, bg="black")
			frame1.pack()
			frame2 = tk.Frame(window, bg="black")
			frame2.pack()
			
			def paste():
				messagetodec.insert(tk.END, pyperclip.paste())
				
			def decrypt():
				try:
					#Functions
					encryptedmessage = ""
					password = ""
					decryptedmessage = ""
					
					backend = default_backend()
					iterations = 100_000
	
					def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
						kdf = PBKDF2HMAC(
							algorithm=hashes.SHA256(), length=32, salt=salt,
						iterations=iterations, backend=backend)
						return b64e(kdf.derive(password))
						
					def password_decrypt(token: bytes, password: str) -> bytes:
							decoded = b64d(token)
							salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
							iterations = int.from_bytes(iter, 'big')
							key = _derive_key(password.encode(), salt, iterations)
							return Fernet(key).decrypt(token)
					
					encryptedmessage = messagetodec.get("1.0", tk.END)
					password = passentry.get()
					decryptedmessage = password_decrypt(encryptedmessage, password).decode()
					decrypted_text["state"] = "normal"
					decrypted_text.insert(tk.END, decryptedmessage)
				except:
					showerror(title="Error", message="Wrong password!")
					refresh()
					
			
			def exit_decrypt():
				window.destroy()
				menu()
				
			#Widgets
			buttons_style = ttk.Style()
			buttons_style.configure('my.TButton', font=('Times', 10))
			buttons_style.configure('big.TButton', font=('Times', 11, 'bold'))
			
			title = tk.Label(frame1, text="Decrypt",
				fg= "white",
				bg= "black",
				font=("Times", 18, "bold"))
			title.pack(fill=tk.X)
			
			empty = tk.Label(frame1, bg="black").pack(fill=tk.X)
			
			pastebutt = ttk.Button(frame1, text="Paste", style="my.TButton", command=paste)
			pastebutt.pack()
			
			messagetodec = tk.Text(frame1, padx=15, pady=15, height=7, font=("Times", 11), wrap="word")
			messagetodec.pack()
			
			empty = tk.Label(frame1, bg="black").pack(fill=tk.X)	
			
			labelpass = tk.Label(frame1, bg="black", fg="white", text="Password: ", font=("Times", 12)).pack(fill=tk.X)
			
			passentry = tk.Entry(frame1, justify="center", font=("Times", 11))
			passentry.pack()
			
			empty = tk.Label(frame1, bg="black").pack(fill=tk.X)
			
			decryptbutton = ttk.Button(frame1, text="Decrypt", style="big.TButton", command=decrypt)
			decryptbutton.pack()
			
			empty = tk.Label(frame1,bg="black").pack(fill=tk.X)
			
			decrypted_text = tk.Text(frame1, padx=15, pady=15, height=7, font=("Times", 11), wrap="word", state="disabled")
			decrypted_text.pack()
			
			empty = tk.Label(frame2, text="\n", bg="black").pack(fill=tk.X)
			
			refreshbutton = ttk.Button(frame2, text="Refresh", style="my.TButton", command=refresh)
			refreshbutton.pack(side=tk.LEFT)
			
			empty = tk.Label(frame2, bg="black").pack(side=tk.LEFT)
			
			exitbutton = ttk.Button(frame2, text="Exit", style="my.TButton", command=exit_decrypt)
			exitbutton.pack(side=tk.LEFT)
			
		start_gui()
		
	#Widgets
	buttons_style = ttk.Style()
	buttons_style.configure('my.TButton', font=('Times', 10))
	
	#Image
	logo = tk.PhotoImage(file="simcrypt.png")
	smallerlogo = logo.subsample(2, 2)
	uriel = tk.Label(image=smallerlogo, bg='black')
	uriel.pack(fill=tk.X)
	
	empty = tk.Label(text="", bg="grey")
	empty.pack(fill=tk.X)
	
	empty = tk.Label(bg="black")
	empty.pack(fill=tk.X)
	
	nascondibutt = ttk.Button(text="Encrypt",style="my.TButton", command=encryption)
	nascondibutt.pack()
	
	empty = tk.Label(bg="black")
	empty.pack(fill=tk.X)
	
	estraibutt = ttk.Button(text="Decrypt", style="my.TButton", command=decryption)
	estraibutt.pack()
	
	empty = tk.Label(bg="black")
	empty.pack(fill=tk.X)
	
	empty = tk.Label(text="", bg="grey")
	empty.pack(fill=tk.X)
	
	empty = tk.Label(bg="black", text="")
	empty.pack(fill=tk.X)
	
	#Image
	uriellogo = tk.PhotoImage(file="uriel-white.png")
	smallerlogo2 = uriellogo.subsample(3, 3)
	uriel2 = tk.Label(image=smallerlogo2, bg='black')
	uriel2.pack(fill=tk.X)
	
	powered = tk.Label(text="powered by Uriel-SG", font=("Calibri", 8), bg="grey")
	powered.pack(fill=tk.X, side=tk.BOTTOM)
	
	empty = tk.Label(bg="black")
	empty.pack(fill=tk.X, side=tk.BOTTOM)
	
	def exitall():
		finestra.destroy()
			
	esci = ttk.Button(text="Esci", style="my.TButton", command=exitall)
	esci.pack(side=tk.BOTTOM)
	
	finestra.mainloop()

menu()
