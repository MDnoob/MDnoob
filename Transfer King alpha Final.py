import socket
import os
import tqdm
import threading
from tkinter import filedialog, Tk, Button, Label, Entry
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

# Key exchange and encryption functions
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def save_public_key(public_key, filename="public_key.pem"):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as key_file:
        key_file.write(serialized_key)

def load_public_key(filename="public_key.pem"):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), default_backend())
    return public_key

def derive_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    return shared_key

def encrypt_data(data, shared_key):
    cipher = shared_key[:16]  # Use the first 16 bytes of the shared key as the encryption key
    iv = shared_key[16:32]  # Use the next 16 bytes as the IV (Initialization Vector)
    encryptor = Cipher(algorithms.AES(cipher), modes.CFB(iv), default_backend()).encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def decrypt_data(encrypted_data, shared_key):
    cipher = shared_key[:16]  # Use the first 16 bytes of the shared key as the encryption key
    iv = shared_key[16:32]  # Use the next 16 bytes as the IV (Initialization Vector)
    decryptor = Cipher(algorithms.AES(cipher), modes.CFB(iv), default_backend()).decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

def update_path(entry, is_for_sending):
    if is_for_sending:
        filename = filedialog.askopenfilename(title="Select a file to send")
    else:
        filename = filedialog.askdirectory(title="Select a destination folder")
    entry.delete(0, 'end')
    entry.insert(0, filename)

def handle_button_click(action, file_entry, root, public_key=None, private_key=None):
    # Clear existing widgets
    for widget in root.winfo_children():
        widget.destroy()

    # IP Address Label and Entry
    ip_label = Label(root, text="Your IP Address:")
    ip_label.grid(row=0, column=0, padx=10, pady=10)

    ip_entry = Entry(root)
    ip_entry.insert(0, get_local_ip())
    ip_entry.grid(row=0, column=1, padx=10, pady=10)

    # File Path Label and Entry
    file_label = Label(root, text="File Path:")
    file_label.grid(row=1, column=0, padx=10, pady=10)

    file_entry = Entry(root)
    file_entry.grid(row=1, column=1, padx=10, pady=10)

    # Browse Button to select file or destination
    browse_button_text = "Browse"
    browse_command = lambda: update_path(file_entry, action == "send")
    browse_button = Button(root, text=browse_button_text, command=browse_command)
    browse_button.grid(row=1, column=2, padx=10, pady=10)

    if action == "send":
        # Receiver's IP Label and Entry for send
        receiver_ip_label = Label(root, text="Receiver's IP:")
        receiver_ip_label.grid(row=2, column=0, padx=10, pady=10)

        receiver_ip_entry = Entry(root)
        receiver_ip_entry.grid(row=2, column=1, padx=10, pady=10)

        # OK Button to start sending
        ok_button = Button(root, text="OK", command=lambda: start_sending_threaded(file_entry, ip_entry, public_key, private_key, receiver_ip_entry), bg="green", fg="white")
        ok_button.grid(row=3, column=1, padx=10, pady=20)
    elif action == "receive":
        # Destination Label and Entry for receive
        destination_label = Label(root, text="Save As:")
        destination_label.grid(row=2, column=0, padx=10, pady=10)

        destination_entry = Entry(root)
        destination_entry.grid(row=2, column=1, padx=10, pady=10)

        # Browse Button to select destination
        browse_button = Button(root, text="Browse", command=lambda: update_path(destination_entry, False))
        browse_button.grid(row=2, column=2, padx=10, pady=10)

        # OK Button to start receiving
        ok_button = Button(root, text="OK", command=lambda: start_receiving_threaded(destination_entry, root, private_key), bg="blue", fg="white")
        ok_button.grid(row=3, column=1, padx=10, pady=20)

def start_receiving_threaded(destination_entry, root, private_key):
    # Start receiving in a new thread
    receive_thread = threading.Thread(target=start_receiving, args=(destination_entry, root, private_key))
    receive_thread.start()

def start_receiving(destination_entry, root, private_key):
    try:
        # Get the destination path from the entry widget
        save_path = destination_entry.get()

        # Check if a destination is selected
        if not save_path:
            print("No destination selected. Exiting.")
            return

        # Existing code for receiving
        SERVER_HOST = get_local_ip()
        SERVER_PORT = 5001

        s = socket.socket()
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen(1)
        print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
        print("Waiting for the client to connect... ")
        client_socket, address = s.accept()
        print(f"[+] {address} is connected.")

        # Send public key to the client
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(public_key_bytes)

        received = client_socket.recv(BUFFER_SIZE)
        encrypted_shared_key = received[:256]  # The first 256 bytes are for the encrypted shared key
        encrypted_filename = received[256:]  # The rest is the encrypted filename

        # Decrypt the shared key using the private key
        shared_key = private_key.decrypt(encrypted_shared_key, ec.ECIES(hashes.SHA256()))

        # Decrypt the filename using the shared key
        filename = decrypt_data(encrypted_filename, shared_key)
        filename = filename.decode()

        # Combine the received file name with the selected destination path
        file_path = os.path.join(save_path, filename)

        progress = tqdm.tqdm(range(100), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)

        with open(file_path, "wb") as f:
            total_received = 0
            while True:
                bytes_read = client_socket.recv(BUFFER_SIZE)
                if not bytes_read:
                    break

                # Decrypt the data using the shared key
                decrypted_data = decrypt_data(bytes_read, shared_key)

                f.write(decrypted_data)
                total_received += len(bytes_read)

                # Update the progress bar
                progress.update(len(bytes_read))
                if total_received == 100:
                    break

        progress.close()

        client_socket.close()
        s.close()
        print("[+] File received successfully.")
    except Exception as e:
        print(f"Error during receiving: {e}")
    finally:
        # Close the root window even if an error occurs
        root.destroy()

def start_sending_threaded(file_entry, ip_entry, public_key, private_key, receiver_ip_entry):
    # Start sending in a new thread
    send_thread = threading.Thread(target=start_sending, args=(file_entry, ip_entry, public_key, private_key, receiver_ip_entry))
    send_thread.start()

def start_sending(file_entry, ip_entry, public_key, private_key, receiver_ip_entry):
    try:
        # Get the file path from the entry widget
        filename = file_entry.get()

        # Check if a file is selected
        if not filename:
            print("No file selected. Exiting.")
            return

        # Get the receiver's IP address from the entry widget
        receiver_ip = receiver_ip_entry.get()

        # Check if a valid IP address is entered
        if not receiver_ip:
            print("No receiver IP entered. Exiting.")
            return

        # Existing code for sending
        port = 5001

        s = socket.socket()
        print(f"[+] Connecting to {receiver_ip}:{port}")
        s.connect((receiver_ip, port))
        print("[+] Connected to ", receiver_ip)

        # Send public key to the server
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.send(public_key_bytes)

        # Generate a shared key and encrypt it using the server's public key
        shared_key = os.urandom(32)  # 256-bit shared key
        encrypted_shared_key = public_key.encrypt(shared_key, ec.ECIES(hashes.SHA256()))

        # Encrypt the filename using the shared key
        encrypted_filename = encrypt_data(os.path.basename(filename).encode(), shared_key)

        # Send the encrypted shared key and filename to the server
        s.send(encrypted_shared_key + encrypted_filename)

        filesize = os.path.getsize(filename)
        progress = tqdm.tqdm(total=filesize, unit="B", unit_scale=True, unit_divisor=1024, desc=f"Sending {filename}")

        with open(filename, "rb") as f:
            total_sent = 0
            while True:
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break

                # Encrypt the data using the shared key
                encrypted_data = encrypt_data(bytes_read, shared_key)

                s.sendall(encrypted_data)
                total_sent += len(bytes_read)

                # Update the progress bar
                progress.update(len(bytes_read))
                if total_sent == 100:
                    break

        progress.close()

        s.close()
        print("[+] File sent successfully.")
    except Exception as e:
        print(f"Error during sending: {e}")

# Create UI
root = Tk()
root.title("File Transfer App")

# Generate and save the public and private keys
private_key, public_key = generate_key_pair()
save_public_key(public_key)

# IP Address Label and Entry
ip_label = Label(root, text="Your IP Address:")
ip_label.grid(row=0, column=0, padx=10, pady=10)

ip_entry = Entry(root)
ip_entry.insert(0, get_local_ip())
ip_entry.grid(row=0, column=1, padx=10, pady=10)

# File Path Label and Entry
file_label = Label(root, text="File Path:")
file_label.grid(row=1, column=0, padx=10, pady=10)

file_entry = Entry(root)
file_entry.grid(row=1, column=1, padx=10, pady=10)

# Browse Button to select file or destination
browse_button = Button(root, text="Browse", command=lambda: update_path(file_entry, True))
browse_button.grid(row=1, column=2, padx=10, pady=10)

# Send Button
send_button = Button(root, text="Send", command=lambda: handle_button_click("send", file_entry, root, public_key, private_key), bg="green", fg="white")
send_button.grid(row=2, column=0, padx=10, pady=20)

# Receive Button
receive_button = Button(root, text="Receive", command=lambda: handle_button_click("receive", file_entry, root, public_key, private_key), bg="blue", fg="white")
receive_button.grid(row=2, column=1, padx=10, pady=20)

root.mainloop()
