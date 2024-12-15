import socket
import json
import random
import math
from des import ascii2bin, bin2ascii, permute, shift_left, encrypt_text, decrypt_text, keyp, key_comp, shift_table

prime_numbers = []

# Generate bilangan prima
def generate_primes():
    global prime_numbers
    sieve = [True] * 250
    sieve[0] = sieve[1] = False
    for i in range(2, 250):
        if sieve[i]:
            for j in range(i * i, 250, i):
                sieve[j] = False
    prime_numbers = [i for i, is_prime in enumerate(sieve) if is_prime]

# Generate RSA keys
def generate_rsa_keys():
    p = random.choice(prime_numbers)
    q = random.choice(prime_numbers)
    while q == p:
        q = random.choice(prime_numbers)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while math.gcd(e, phi) != 1:
        e += 2

    d = pow(e, -1, phi)
    return (e, n), (d, n)

# Enkripsi dengan kunci publik
def encrypt_message(message, public_key):
    e, n = public_key
    encrypted = [pow(ord(char), e, n) for char in message]
    return json.dumps(encrypted)  # Convert to JSON string for transmission

# Dekripsi dengan kunci privat
def decrypt_message(encrypted_message, private_key):
    d, n = private_key

    # Convert the JSON string to a list of integers
    if isinstance(encrypted_message, str):
        encrypted_message = json.loads(encrypted_message)
        encrypted_message = [int(char) for char in encrypted_message]  # Ensure integers

    # Perform decryption
    decrypted = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted

# Koneksi ke server
def connect_to_server():
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    return client_socket

# Registrasi kunci
def register_key(client_socket, client_id, public_key, n):
    request = {"action": "register", "id": client_id, "public_key": public_key, "n": n}
    client_socket.send(json.dumps(request).encode())
    response = client_socket.recv(4096).decode()
    print("Response from server:", response)

# Mendapatkan kunci publik
def get_key(client_socket, target_id):
    request = {"action": "get_key", "id": target_id}
    client_socket.send(json.dumps(request).encode())
    response = client_socket.recv(4096).decode()
    response_data = json.loads(response)
    if response_data.get("status") == "success":
        return response_data.get("data")
    else:
        print("Error:", response_data.get("message"))
        return None

def handshake_sender(client_socket, client_id, public_key, private_key):
    target_id = input("Enter target ID for handshake: ")

    # Langkah 1-2: Dapatkan kunci publik target
    target_key = get_key(client_socket, target_id)
    if not target_key:
        print("Failed to retrieve target key.")
        return False
    target_public_key = (int(target_key["public_key"]), int(target_key["n"]))
    print("Target public key:", target_public_key)

    # Langkah 3: Kirim n1 dan id dengan action send_message
    n1 = random.randint(1000, 9999)
    message = {"n1": n1, "id": client_id}
    print("Sending handshake initiation:", message)
    encrypted_message = encrypt_message(json.dumps(message), target_public_key)

    # Bungkus dalam JSON dengan action "send_message"
    request = {
        "action": "send_message",
        "message": encrypted_message
    }
    print("Request being sent:", request)
    client_socket.send(json.dumps(request).encode())

    # Langkah 4: Terima n1 dan n2 dari target
    n1n2_raw_data = client_socket.recv(4096).decode()

    # Parse JSON data
    n1n2_data = json.loads(n1n2_raw_data)
    print("Parsed data from receiver:", n1n2_data)

    if n1n2_data.get("action") != "send_message" or "message" not in n1n2_data:
            print("Invalid message format or action.")
            return False
    
    decrypted_n1n2 = n1n2_data["message"]
    decrypted_n1n2 = decrypt_message(decrypted_n1n2, private_key)
    decrypted_n1n2 = json.loads(decrypted_n1n2)
    print("Decrypted n1n2 data:", decrypted_n1n2)

    n1_received = decrypted_n1n2.get("n1")
    n2 = decrypted_n1n2.get("n2")
    if n1_received != n1:
        print("Failed: Invalid n1 received.")
        return False
    
    response_n2 = {"n2": n2}
    encrypted_response_n2 = encrypt_message(json.dumps(response_n2), target_public_key)

    request2 = {
        "action": "send_message",
        "message": encrypted_response_n2
    }
    print("Request 2 being sent:", request2)
    client_socket.send(json.dumps(request2).encode())

    # Langkah 5: Terima kunci DES
    data = client_socket.recv(4096).decode()
    print("Received DES key data:", data)

    # Parse JSON data
    data = json.loads(data)
    print("Parsed data:", data)

    # Ambil dan dekripsi pesan
    encrypted_des_key = data["message"]
    print("Encrypted DES key:", encrypted_des_key)
    decrypted_des_key = decrypt_message(encrypted_des_key, private_key)
    print("Decrypted DES key 1:", decrypted_des_key)
    decrypted_des_key = decrypt_message(decrypted_des_key, target_public_key)
    print("Decrypted DES key 2:", decrypted_des_key)

    fix_des_key = decrypted_des_key
    fix_des_key = ascii2bin(fix_des_key)
    fix_des_key = permute(fix_des_key, keyp, 56)

    left = fix_des_key[:28]
    right = fix_des_key[28:]

    rkb = []
    rk = []
    for i in range(16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
            
        # Combination of left and right string
        combine_str = left + right
            
        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)
        
        rkb.append(round_key)
        rk.append(bin2ascii(round_key))

    # Communication loop
    print("Connected to the server. Type 'bye' to exit.")
    message = input(" -> ")
    while message.lower().strip() != "bye":
        encrypted_message = encrypt_text(message, rkb, rk)
        request = {"action": "send_message", "message": encrypted_message}
        client_socket.send(json.dumps(request).encode())

        data = client_socket.recv(4096).decode()
        data = json.loads(data)
        data = data["message"]
        decrypted_message = decrypt_text(data, rkb[::-1], rk[::-1])

        print("Received from other client before decrypt:", data)
        print("Received from other client:", decrypted_message)

        message = input(" -> ")


def handshake_receiver(client_socket, client_id, public_key, private_key):
    try:
        # Langkah 1: Terima data JSON dari sender
        raw_data = client_socket.recv(4096).decode()

        # Parse JSON data
        data = json.loads(raw_data)
        print("Parsed data from sender:", data)

        # Pastikan ini adalah pesan dengan action "send_message"
        if data.get("action") != "send_message" or "message" not in data:
            print("Invalid message format or action.")
            return False

        # Ambil dan dekripsi pesan
        encrypted_message = data["message"]
        decrypted_message = decrypt_message(encrypted_message, private_key)
        decrypted_message = json.loads(decrypted_message)  # Decode JSON dalam pesan

        # Ekstrak n1 dan sender_id
        n1 = decrypted_message.get("n1")
        sender_id = decrypted_message.get("id")
        if not n1 or not sender_id:
            print("Failed: Invalid handshake initiation.")
            return False

        print(f"Received handshake request from {sender_id} with n1={n1}")

        # Langkah 2: Ambil kunci publik sender
        sender_key = get_key(client_socket, sender_id)
        if not sender_key:
            print("Failed to retrieve sender key.")
            return False
        sender_public_key = (int(sender_key["public_key"]), int(sender_key["n"]))
        print("Sender public key:", sender_public_key)

        # Langkah 3: Kirim n1 kembali ke sender
        n2 = random.randint(1000, 9999)
        response = {"n1": n1, "n2": n2}
        encrypted_response = encrypt_message(json.dumps(response), sender_public_key)
        print("Sent encrypted response:", response)
        # Bungkus dalam JSON dengan action "send_message"
        request = {
            "action": "send_message",
            "message": encrypted_response
        }
        print("Request being sent:", request)
        client_socket.send(json.dumps(request).encode())

        # Langkah 4: Terima n2 dari sender
        data = client_socket.recv(4096).decode()

        # Parse JSON data
        data = json.loads(data)
        print("Parsed data:", data)

        # Ambil dan dekripsi pesan
        encrypted_n2 = data["message"]
        decrypted_n2 = decrypt_message(encrypted_n2, private_key)
        decrypted_n2 = json.loads(decrypted_n2)  # Decode JSON dalam pesan

        n2_received = decrypted_n2.get("n2")
        if n2_received != n2:
            print("Failed: Invalid n2 received.")
            return False
        
        print("Handshake successful.\n")

        DES_key = input("Enter DES key: ")
        first_encrypted_des_key = encrypt_message(DES_key, private_key)
        print("First encrypted DES key:", first_encrypted_des_key)
        second_encrypted_des_key = encrypt_message(first_encrypted_des_key, sender_public_key)
        print("Second encrypted DES key:", second_encrypted_des_key)

        request2 = {
            "action": "send_message",
            "message": second_encrypted_des_key
        }
        print("DES Key being sent:", request2)
        client_socket.send(json.dumps(request2).encode())
        
        fix_des_key = DES_key
        fix_des_key = ascii2bin(fix_des_key)
        fix_des_key = permute(fix_des_key, keyp, 56)

        left = fix_des_key[:28]
        right = fix_des_key[28:]

        rkb = []
        rk = []
        for i in range(16):
            # Shifting the bits by nth shifts by checking from shift table
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            
            # Combination of left and right string
            combine_str = left + right
            
            # Compression of key from 56 to 48 bits
            round_key = permute(combine_str, key_comp, 48)
            
            rkb.append(round_key)
            rk.append(bin2ascii(round_key))

        # Communication loop
        print("Connected to the server. Type 'bye' to exit.")
        message = input(" -> ")
        while message.lower().strip() != "bye":
            encrypted_message = encrypt_text(message, rkb, rk)
            request = {"action": "send_message", "message": encrypted_message}
            client_socket.send(json.dumps(request).encode())

            data = client_socket.recv(4096).decode()
            data = json.loads(data)
            data = data["message"]
            decrypted_message = decrypt_text(data, rkb[::-1], rk[::-1])

            print("Received from other client before decrypt:", data)
            print("Received from other client:", decrypted_message)

            message = input(" -> ")

    except Exception as e:
        print(f"Error during handshake: {e}")
        return False

# Program utama
def client_program(role):
    generate_primes()
    client_socket = connect_to_server()

    client_id = input("Enter your ID: ")
    public_key, private_key = generate_rsa_keys()
    print("Your public key:", public_key)
    print("Your private key:", private_key)
    register_key(client_socket, client_id, public_key[0], public_key[1])

    if role == "sender":
        if handshake_sender(client_socket, client_id, public_key, private_key):
            print("Secure communication established.")
        else:
            return
    elif role == "receiver":
        if handshake_receiver(client_socket, client_id, public_key, private_key):
            print("Secure communication established.")
        else:
            return

    client_socket.close()

if __name__ == "__main__":
    role = input("Enter your role (sender/receiver): ")
    client_program(role)