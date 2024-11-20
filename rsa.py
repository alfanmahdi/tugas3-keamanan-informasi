import random, rabinMiller, cryptomath

def generateKey(keySize):
  # Step 1: Create two prime numbers, p and q. Calculate n = p * q.
  print('Generating p prime...')
  p = rabinMiller.generateLargePrime(keySize)
  print('Generating q prime...')
  q = rabinMiller.generateLargePrime(keySize)
  n = p * q
  
  # Step 2: Create a number e that is relatively prime to (p-1)*(q-1).
  print('Generating e that is relatively prime to (p-1)*(q-1)...')
  while True:
      e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
      if cryptomath.gcd(e, (p - 1) * (q - 1)) == 1:
        break
  
  # Step 3: Calculate d, the mod inverse of e.
  print('Calculating d that is mod inverse of e...')
  d = cryptomath.findModInverse(e, (p - 1) * (q - 1))
  publicKey = (n, e)
  privateKey = (n, d)
  # print('Public key:', publicKey)
  # print('Private key:', privateKey)
  return (publicKey, privateKey)

def encrypt(publicKey, message):
  (n, e) = publicKey
  
  message_bytes = message.encode('utf-8')
  message_int = int.from_bytes(message_bytes, byteorder='big')

  encrypted_int = pow(message_int, e, n)
  return encrypted_int

def decrypt(privateKey, encrypted_int):
  n, d = privateKey
  decrypted_int = pow(encrypted_int, d, n)
  decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
  return decrypted_bytes.decode('utf-8')

# publicKey, privateKey = generateKey(1024)
# message = 'Hello, this message contains more than 8 characters. Not like the previous one.'
# print('Original message:', message)
# encrypted = encrypt(publicKey, message)
# print('Encrypted message:', encrypted)
# decrypted = decrypt(privateKey, encrypted)
# print('Decrypted message:', decrypted)