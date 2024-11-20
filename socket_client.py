import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tugas1KI_desAlgorithm import encrypt_text, decrypt_text, rkb, rk

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def send_public_key_to_pka(name, public_key):
    host = socket.gethostname()  # PKA host (adjust as needed)
    port = 5001                  # PKA port

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))

        key_data = json.dumps({"action": "register", "name": name, "public_key": public_key.decode()})
        pka_socket.send(key_data.encode())

        response = pka_socket.recv(2048).decode()
        print("Response from PKA:", response)

        pka_socket.close()
    except Exception as e:
        print(f"Error sending key to PKA: {e}")

def get_public_key_from_pka(name):
    host = socket.gethostname()  # PKA host (adjust as needed)
    port = 5001                  # PKA port

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))

        key_request = json.dumps({"action": "get_key", "name": name})
        pka_socket.send(key_request.encode())

        response = pka_socket.recv(2048).decode()
        pka_socket.close()

        key_data = json.loads(response)
        return key_data.get("public_key")
    except Exception as e:
        print(f"Error retrieving key from PKA: {e}")
        return None

def rsa_encrypt_message(message, recipient_public_key):
    recipient_key = RSA.import_key(recipient_public_key.encode())
    cipher = PKCS1_OAEP.new(recipient_key)
    return cipher.encrypt(message.encode())

def rsa_decrypt_message(encrypted_message, private_key):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()

def client_program():
    # Generate RSA key pair
    private_key, public_key = generate_key_pair()

    # Register the public key with the PKA
    client_name = input("Enter your client name: ")
    send_public_key_to_pka(client_name, public_key)

    # Ask for the recipient's name
    recipient_name = input("Enter the recipient's name: ")
    recipient_public_key = get_public_key_from_pka(recipient_name)

    if not recipient_public_key:
        print("Recipient's public key not found!")
        return

    # print(f"Retrieved public key for {recipient_name}: {recipient_public_key}")

    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    print("Connected to the server. Type 'bye' to exit.")
    message = input(" -> ")

    while message.lower().strip() != 'bye':
        # Encrypt the message using recipient's public key
        encrypted_message = rsa_encrypt_message(message, recipient_public_key)
        client_socket.send(encrypted_message)

        # Receive and decrypt the response
        encrypted_response = client_socket.recv(2048)
        decrypted_response = rsa_decrypt_message(encrypted_response, private_key)

        print("Received from other client:", decrypted_response)

        message = input(" -> ")
    client_socket.close()

if __name__ == '__main__':
    client_program()
