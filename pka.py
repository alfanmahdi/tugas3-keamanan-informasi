import socket
import threading
import json

# Simulated PKA storage for public keys
public_key_storage = {}

# File to persist public keys
KEY_FILE = "public_keys.json"

# Load existing keys from file
def load_keys():
    try:
        with open(KEY_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save keys to file
def save_keys():
    with open(KEY_FILE, 'w') as f:
        json.dump(public_key_storage, f, indent=4)

# Load keys at startup
public_key_storage = load_keys()

# Handle incoming connections to register/retrieve public keys
def handle_client(conn, address):
    print(f"Connection from {address}")
    try:
        data = conn.recv(2048).decode()
        if data:
            request = json.loads(data)
            action = request.get("action")

            if action == "register":
                name = request.get("name")
                public_key = request.get("public_key")
                if name and public_key:
                    public_key_storage[name] = public_key
                    save_keys()
                    print(f"Registered public key for {name}")
                    conn.send("Key registered successfully!".encode())
                else:
                    conn.send("Invalid registration data!".encode())

            elif action == "get_key":
                name = request.get("name")
                public_key = public_key_storage.get(name)
                if public_key:
                    conn.send(json.dumps({"name": name, "public_key": public_key}).encode())
                else:
                    conn.send("Key not found!".encode())
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        conn.close()

# Start the PKA server
def start_pka_server():
    host = '0.0.0.0'  # Listen on all interfaces
    port = 5001       # Port for PKA

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("PKA server is running... Waiting for connections.")
    while True:
        conn, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, address)).start()

if __name__ == '__main__':
    start_pka_server()
