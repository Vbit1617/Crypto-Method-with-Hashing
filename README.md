pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key_hash(key):
    return SHA256.new(key).digest()

def generate_file_hash(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        return SHA256.new(data).digest()

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_file(file_path, public_key_path, output_path, private_key_sender):
    with open(public_key_path, 'rb') as file:
        public_key_receiver = RSA.import_key(file.read())

    # Generate a random symmetric key for AES encryption
    symmetric_key = get_random_bytes(32)  # Use a 256-bit key for AES
    iv = get_random_bytes(16)

    # Encrypt the symmetric key with the receiver's public key
    cipher_rsa = PKCS1_OAEP.new(public_key_receiver, hashAlgo=SHA256)
    encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    # Sign the symmetric key with the sender's private key
    signature = sign_message(symmetric_key, private_key_sender)

    # Encrypt the file content with AES using the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    # Save the encrypted data, IV, and encrypted signature
    with open(output_path, 'wb') as file:
        file.write(encrypted_symmetric_key)
        file.write(signature)
        file.write(iv)
        file.write(ciphertext)

    input_file_hash = generate_file_hash(file_path)
    print("Input File Hash:", input_file_hash.hex())

    # Generate and display the hash of the encrypted file
    encrypted_file_hash = generate_file_hash(output_path)
    print("Encrypted File Hash:", encrypted_file_hash.hex())
    print("Encryption successful.")

def decrypt_file(encrypted_path, private_key_path, public_key_sender_path, output_path):
    with open(private_key_path, 'rb') as file:
        private_key_receiver = RSA.import_key(file.read())

    with open(public_key_sender_path, 'rb') as file:
        public_key_sender = RSA.import_key(file.read())

    # Read the encrypted symmetric key, encrypted signature, IV, and ciphertext
    with open(encrypted_path, 'rb') as file:
        encrypted_symmetric_key = file.read(256)
        signature = file.read(256)
        iv = file.read(16)
        ciphertext = file.read()

    # Decrypt the symmetric key with the receiver's private key
    cipher_rsa = PKCS1_OAEP.new(private_key_receiver, hashAlgo=SHA256)
    symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)

    # Verify the digital signature of the symmetric key with sender's public key
    if verify_signature(symmetric_key, signature, public_key_sender.export_key()):
        print("Signature verification successful.")
        # Decrypt the file content with AES using the decrypted symmetric key and IV
        cipher_aes = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

        # Save the decrypted file data
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        # Generate and display the hash of the decrypted file
        decrypted_file_hash = generate_file_hash(output_path)
        print("Decrypted File Hash:", decrypted_file_hash.hex())
        print("Decryption successful.")
    else:
        print("Signature verification failed. Aborting decryption.")

# User 1 (Sender)
private_key_user1, public_key_user1 = generate_key_pair()
with open('private_key_user1.pem', 'wb') as file:
    file.write(private_key_user1)
with open('public_key_user1.pem', 'wb') as file:
    file.write(public_key_user1)

# User 2 (Receiver)
private_key_user2, public_key_user2 = generate_key_pair()
with open('private_key_user2.pem', 'wb') as file:
    file.write(private_key_user2)
with open('public_key_user2.pem', 'wb') as file:
    file.write(public_key_user2)

# Encrypt PNG file by User 1
encrypt_file('sample_image.png', 'public_key_user2.pem', 'encrypted_image.bin', private_key_user1)

# Decrypt PNG file by User 2
decrypt_file('encrypted_image.bin', 'private_key_user2.pem', 'public_key_user1.pem', 'decrypted_image.png')
