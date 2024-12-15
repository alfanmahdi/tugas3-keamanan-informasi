import socket
import json
import random
import math
import cryptomath
from tugas1KI_desAlgorithm import ascii2bin, bin2ascii, xor, permute, keyp, shift_left, shift_table, key_comp, bin2hex, encrypt_text, decrypt_text

# A set will be the collection of prime numbers, where we can select random primes p and q
primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

# Set public and private keys
def setkeys():
    p, q = random.sample(primes, 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while math.gcd(e, phi) != 1:
        e += 1
    
    d = cryptomath.findModInverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    return public_key, private_key

# Encrypt a number
def encrypt(message, key, n):
    return pow(message, key, n)

# Decrypt a number
def decrypt(encrypted_text, key, n):
    return pow(encrypted_text, key, n)

# Encode a list of numbers
def encoder(message_list, key, n):
    return [encrypt(num, key, n) for num in message_list]

# Decode a list of numbers
def decoder(encoded_list, key, n):
    return [decrypt(num, key, n) for num in encoded_list]

# Convert a string to a list of ASCII values
def string_to_ascii(message):
    return [ord(char) for char in message]

# Convert a list of ASCII values back to a string
def ascii_to_string(ascii_list):
    return ''.join(chr(num) for num in ascii_list)

# Send public key to PKA
def send_public_key_to_pka(name, public_key):
    host = socket.gethostname()
    port = 5001
    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        key_data = json.dumps({"action": "register", "name": name, "public_key": public_key})
        pka_socket.send(key_data.encode())
        response = pka_socket.recv(2048).decode()
        print("Response from PKA:", response)
        pka_socket.close()
    except Exception as e:
        print(f"Error sending key to PKA: {e}")

# Retrieve public key from PKA
def get_public_key_from_pka(name):
    host = socket.gethostname()
    port = 5001
    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        key_request = json.dumps({"action": "get_key", "name": name})
        pka_socket.send(key_request.encode())
        response = pka_socket.recv(2048).decode()
        pka_socket.close()
        key_data = json.loads(response)
        return tuple(map(int, key_data.get("public_key")))
    except Exception as e:
        print(f"Error retrieving key from PKA: {e}")
        return None

# Check and set keys
def check_and_set_keys(name):
    public_key = get_public_key_from_pka(name)
    if public_key:
        print(f"Public key for {name} already registered with PKA.")
        return public_key, None
    else:
        print(f"No existing public key found for {name}. Generating new keys.")
        public_key, private_key = setkeys()
        send_public_key_to_pka(name, public_key)
        return public_key, private_key

# Handshake mechanism to establish connection and verify public keys
def handshake(client_socket, client_name, client_public_key, other_public_key):
    try:
        handshake_data = json.dumps({"action": "handshake", "name": client_name, "public_key": client_public_key})
        client_socket.send(handshake_data.encode())
        response = client_socket.recv(2048).decode()
        response_data = json.loads(response)
        if tuple(response_data.get("public_key")) == other_public_key:
            print("Handshake successful. Public key verified.")
            return True
        else:
            print("Handshake failed. Public key verification failed.")
            return False
    except Exception as e:
        print(f"Error during handshake: {e}")
        return False

# Main client program
def client_program():
    role = input("Sender/Receiver: ").strip().lower()
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    client_name = input("Enter your name: ")
    client_public_key, client_private_key = check_and_set_keys(client_name)
    print(client_private_key)

    if role == "sender":
        recipient_name = input("Enter the recipient's name: ")
        recipient_public_key = get_public_key_from_pka(recipient_name)
        if not recipient_public_key:
            print("Recipient's public key not found!")
            return
        
        print(f"Public Key Sender: {client_public_key}")
        print(f"Public Key Receiver: {recipient_public_key}")
        print(f"Private Key Sender: {client_private_key}")

        if not handshake(client_socket, client_name, client_public_key, recipient_public_key):
            print("Handshake failed. Exiting.")
            client_socket.close()
            return

        des_key = "haloBandung"
        des_key_ascii = string_to_ascii(des_key)
        first_encrypted_des_key = encoder(des_key_ascii, client_private_key[0], client_private_key[1])
        print(f"First encrypted DES key: {first_encrypted_des_key}")

        second_encrypted_des_key = encoder(first_encrypted_des_key, recipient_public_key[0], recipient_public_key[1])
        print(f"Second encrypted DES key: {second_encrypted_des_key}")
        
        encrypted_key_json = json.dumps(second_encrypted_des_key)
        client_socket.send(encrypted_key_json.encode())
        print("Encrypted DES key sent.")

        fixDESKey = ascii2bin(des_key)

        fixDESKey = permute(fixDESKey, keyp, 56)

        left = fixDESKey[:28]
        right = fixDESKey[28:]

        rkb = []
        rk = []
        for i in range(16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])

            combine_str = left + right

            round_key = permute(combine_str, key_comp, 48)

            rkb.append(round_key)
            rk.append(bin2hex(round_key))

        # Communication loop
        print("Connected to the server. Type 'bye' to exit.")
        message = input(" -> ")
        while message.lower().strip() != "bye":
            encrypted_message = encrypt_text(message, rkb, rk)
            client_socket.send(encrypted_message.encode())

            data = client_socket.recv(2048).decode()
            decrypted_message = decrypt_text(data, rkb[::-1], rk[::-1])

            print("Received from other client before decrypt:", data)
            print("Received from other client:", decrypted_message)

            message = input(" -> ")

    elif role == "receiver":
        sender_name = input("Enter the sender's name: ")
        sender_public_key = get_public_key_from_pka(sender_name)
        if not sender_public_key:
            print("Sender's public key not found!")
            return
        
        print(f"Public Key Sender: {sender_public_key}")
        print(f"Public Key Receiver: {client_public_key}")
        print(f"Private Key Receiver: {client_private_key}")

        if not handshake(client_socket, client_name, client_public_key, sender_public_key):
            print("Handshake failed. Exiting.")
            client_socket.close()
            return

        received_des_key = json.loads(client_socket.recv(2048).decode())
        print(f"Received encrypted DES key: {received_des_key}")

        # First decryption with private key
        first_decrypted_des_key = decoder(received_des_key, client_private_key[0], client_private_key[1])
        print(f"First decrypted DES key: {first_decrypted_des_key}")

        # Second decryption with sender's public key
        second_decrypted_des_key = decoder(first_decrypted_des_key, sender_public_key[0], sender_public_key[1])
        print(f"Second decrypted DES key: {second_decrypted_des_key}")

        # Convert back to string
        des_key_string = ascii_to_string(second_decrypted_des_key)
        print(f"Decrypted DES key (String): {des_key_string}")

        fixDESKey = ascii2bin(des_key_string)

        fixDESKey = permute(fixDESKey, keyp, 56)

        left = fixDESKey[:28]
        right = fixDESKey[28:]

        rkb = []
        rk = []
        for i in range(16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])

            combine_str = left + right

            round_key = permute(combine_str, key_comp, 48)

            rkb.append(round_key)
            rk.append(bin2hex(round_key))

        # Communication loop
        print("Connected to the server. Type 'bye' to exit.")
        message = input(" -> ")
        while message.lower().strip() != "bye":
            encrypted_message = encrypt_text(message, rkb, rk)
            client_socket.send(encrypted_message.encode())

            data = client_socket.recv(2048).decode()
            decrypted_message = decrypt_text(data, rkb[::-1], rk[::-1])

            print("Received from other client before decrypt:", data)
            print("Received from other client:", decrypted_message)

            message = input(" -> ")

    client_socket.close()

if __name__ == "__main__":
    client_program()