import socket
import threading

clients = []

def handle_client(conn, address):
    print("Connection from:", address)
    while True:
        try:
            data = conn.recv(2048)
            if not data:
                break

            print(f"Encrypted message from {address}: {data}")

            # Forward the encrypted message to all other clients
            for client in clients:
                if client != conn:
                    client.send(data)
        except Exception as e:
            print(f"Error handling client {address}: {e}")
            break

    conn.close()
    clients.remove(conn)
    print(f"Connection closed from: {address}")

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
