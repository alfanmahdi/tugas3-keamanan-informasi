import socket
import threading
import json

# Penyimpanan kunci publik (client_id -> {public_key, n})
public_key_storage = {}
clients = []

# File untuk menyimpan kunci publik
KEY_FILE = "public_keys.json"

# Load kunci publik dari file
def load_keys():
    try:
        with open(KEY_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Simpan kunci publik ke file
def save_keys():
    with open(KEY_FILE, 'w') as f:
        json.dump(public_key_storage, f, indent=4)

public_key_storage = load_keys()

# Fungsi untuk menangani klien
def handle_client(conn, address):
    print("Connection from:", address)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            print(f"Encrypted message from {address}: {data}")

            try:
                request = json.loads(data.decode())
            except json.JSONDecodeError:
                conn.send(json.dumps({"status": "error", "message": "Invalid JSON"}).encode())
                continue

            action = request.get("action")

            if action == "register":  # Registrasi kunci publik
                client_id = request.get("id")
                public_key = request.get("public_key")
                n = request.get("n")
                
                if client_id and public_key and n:
                    public_key_storage[client_id] = {"public_key": public_key, "n": n}
                    save_keys()
                    conn.send(json.dumps({"status": "success", "message": "Key registered"}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid data"}).encode())
            
            elif action == "get_key":  # Permintaan kunci publik
                client_id = request.get("id")
                client_data = public_key_storage.get(client_id)
                
                if client_data:
                    conn.send(json.dumps({"status": "success", "data": client_data}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Key not found"}).encode())
            
            elif action == "send_message":  # Kirim pesan ke klien lain
                message = request.get("message")
                if message:
                    # Teruskan pesan ke semua klien lain
                    for client in clients:
                        if client != conn:
                            client.send(data)  # Mengirimkan pesan yang diterima ke klien lain
                else:
                    conn.send(json.dumps({"status": "error", "message": "Message is empty"}).encode())
            
            else:
                conn.send(json.dumps({"status": "error", "message": "Invalid action"}).encode())
                
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        conn.close()
        clients.remove(conn)
        print(f"Connection closed from: {address}")

# Mulai server
def server_program():
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)

    print("Server is running... Waiting for connections.")
    while True:
        conn, address = server_socket.accept()
        clients.append(conn)
        threading.Thread(target=handle_client, args=(conn, address)).start()

if __name__ == '__main__':
    server_program()
