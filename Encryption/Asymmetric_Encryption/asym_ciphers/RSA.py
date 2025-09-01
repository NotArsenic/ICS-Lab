# RSA Algorithm Implementation

import secrets

# --- Helper Functions ---
def _is_prime(n : int, k : int = 10) -> bool:
    """ Check if a large number is prime or not using Miller-Robin Test"""
    
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    
    m, r = n - 1, 0
    
    while m % 2 == 0:
        m //= 2
        r += 1
        
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, m, n)
        
        if x == 1 or x == n - 1:
            continue
        
        is_composite = True
        
        for _ in range (r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_composite = False
                break
            
        if is_composite:
            return False
            
    return True

def _gcd(a : int, b : int) -> int:
    """ Compute GCD of two numbers using Euclidean Algorithm """
    while b:
        a, b = b, a % b
    return a

def _mod_inverse(a : int, m : int) -> int:
    """ Compute Modular Inverse using Extended Euclidean Algorithm """
    
    if _gcd(a, m) != 1:
        raise ValueError(f"Inverse for {a} & {m} doesn't exist")
    
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    
    while v3 != 0:
        quotient = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - quotient * v1), (u2 - quotient * v2), (u3 - quotient * v3), v1, v2, v3
        
    return u1 % m
    

# --- Key Generation ---
def generate_prime(bit_size : int) -> int:
    """ Generate a prime number of specified bit size """
    
    if bit_size < 2:
        raise ValueError("Bit size must be at least 2")
    
    while True:
        num = secrets.randbits(bit_size) | (1 << (bit_size - 1)) | 1
        
        if _is_prime(num):
            return num

def generate_keypair(bit_size : int) -> tuple:
    """ Generate RSA public and private key pair """
    if bit_size % 2 != 0 or bit_size < 16:
        raise ValueError("Bit size must be an even number and at least 16")
    
    prime_size = bit_size // 2  
    e = 65537
    
    while True:
        p = generate_prime(prime_size)
        q = generate_prime(prime_size)
        
        if p == q:
            continue
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if _gcd(e, phi) == 1:
            break
        
    d = _mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

# --- Core Functions ---
def encrypt(plaintext : str, public_key : tuple) -> str:
    """ Encrypt plaintext using RSA public key """
    
    e, n = public_key
    
    key_size = (n.bit_length() + 7) // 8
    
    chunk_size = key_size - 1
    
    plaintext_bytes = plaintext.encode('utf-8')
    
    chunks = [plaintext_bytes[i:i + chunk_size] for i in range(0, len(plaintext_bytes), chunk_size)]
    
    encrypted_chunks = []
    
    for chunk in chunks:
        chunk_int = int.from_bytes(chunk, byteorder='big')
        encrypted_chunk_int = pow(chunk_int, e, n)
        encrypted_chunks.append(encrypted_chunk_int)
        
    ciphertext = ' '.join(map(str, encrypted_chunks))
    return ciphertext

def decrypt(ciphertext : str, private_key : tuple) -> str:
    """ Decrypt ciphertext using RSA private key """
    
    d, n = private_key
    
    key_size = (n.bit_length() + 7) // 8
    
    encrypted_chunks = list(map(int, ciphertext.split()))
    
    decrypted_bytes = bytearray()
    
    for chunk_int in encrypted_chunks:
        decrypted_chunk_int = pow(chunk_int, d, n)
        padded_chunk = decrypted_chunk_int.to_bytes(key_size, byteorder='big')
        unpadded_chunk = padded_chunk.lstrip(b'\x00')
        decrypted_bytes.extend(unpadded_chunk)
        
        
    plaintext = decrypted_bytes.decode('utf-8')
    return plaintext

# --- Testing ---
if __name__ == "__main__":
    print("--- RSA Encryption & Decryption ---")
    print("This program will generate an RSA key pair, then encrypt and decrypt a message.\n")
    
    print("Generating a 1024-bit RSA key pair...")
    public_key, private_key = generate_keypair(bit_size=1024)
    print("Key pair generated successfully.")
    print(f"Generated.... \n\tpublic key:\t{public_key}, \n\tprivate key:\t{private_key}\n")

    test_plaintext = input("\nEnter a message to encrypt: ")

    print("\n--- Encrypting ---")
    print(f"Original Text:  '{test_plaintext}'")
    encrypted_text = encrypt(test_plaintext, public_key)
    print(f"Encrypted Text (string of numbers):\n{encrypted_text}")

    print("\n--- Decrypting ---")
    try:
        decrypted_text = decrypt(encrypted_text, private_key)
        print(f"Decrypted Text: '{decrypted_text}'")

        assert test_plaintext == decrypted_text
        print("\n Verification Successful: The decrypted text matches the original.")

    except (ValueError, AssertionError) as e:
        print(f"\n An error occurred during decryption or verification: {e}")