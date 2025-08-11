import hashlib
import base64

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _f_function(half_block : bytes, key: bytes) -> bytes:
    return _xor(half_block, key)

def _pad(text : bytes, block_size : int) -> bytes:
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1 and 255")
    
    padding_length = block_size - (len(text) % block_size)
    padding = bytes([padding_length] * padding_length)
    
    return text + padding

def _unpad(padded_text : bytes, block_size : int) -> bytes:
    if not padded_text:
        raise ValueError("No text provided!")
    
    padding_length = padded_text[-1]
    
    if padding_length == 0 or padding_length > min(block_size, len(padded_text)):
        raise ValueError(f"Invalid padding length encountered, padding length : {padding_length}")
    
    padding = padded_text[-padding_length:]
    if not all(byte == padding_length for byte in padding):
        raise ValueError("Invalid padding bytes found.")
    
    return padded_text[:-padding_length]

def _key_scheduler(master_key : bytes, rounds : int, key_size : int) -> list[bytes]:
    round_keys = []
    
    for i in range(rounds):
        master_element = master_key + i.to_bytes(1, 'big')
        round_key = hashlib.sha256(master_element).digest()
        round_keys.append(round_key[:key_size])
    
    return round_keys

def _prepare_plaintext(plaintext : str, block_size : int) -> list[bytes]:
    plaintext_bytes = plaintext.encode('utf-8')
    padded_text = _pad(plaintext_bytes, block_size)
    
    blocks = [padded_text[i : i+block_size] for i in range(0, len(padded_text), block_size)]
    
    return blocks

def _encryption_engine(block : bytes, block_size : int, round_keys : list) -> bytes:
    half_block_size = block_size // 2
    
    left, right = block[:half_block_size], block[half_block_size:]
    
    for round_key in round_keys:
        new_left = right
        f_res = _f_function(right, round_key)
        new_right = _xor(left, f_res)
        
        left, right = new_left, new_right
        
    encrypted_block = left + right
    return encrypted_block

def _decryption_engine(block : bytes, block_size : int, round_keys : list) -> bytes:
    half_block_size = block_size // 2
    
    left, right = block[:half_block_size], block[half_block_size:]
    
    for round_key in round_keys:
        new_right = left
        f_res = _f_function(left, round_key)
        new_left = _xor(right, f_res)
        
        left, right = new_left, new_right
        
    decrypted_block = left + right
    return decrypted_block

def encrypt(plaintext : str, master_key : bytes, rounds : int) -> str:
    
    BLOCK_SIZE = 16
    KEY_SIZE = BLOCK_SIZE // 2
    
    key_list = _key_scheduler(master_key, rounds, KEY_SIZE)
    
    text_blocks = _prepare_plaintext(plaintext, BLOCK_SIZE)
    
    encrypted_blocks = []
    
    for block in text_blocks:
        encrypted_block = _encryption_engine(block, BLOCK_SIZE, key_list)
        encrypted_blocks.append(encrypted_block)
    
    encrypted_text_bytes = b''.join(encrypted_blocks)
    return base64.b64encode(encrypted_text_bytes).decode('utf-8')


def decrypt(ciphertext : str, master_key : bytes, rounds : int) -> str:
    
    BLOCK_SIZE = 16
    KEY_SIZE = BLOCK_SIZE // 2
    
    try:
        ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    
    except:
        raise ValueError("Invalid Base64 ciphertext")
    
    text_blocks = [ciphertext_bytes[i : i+BLOCK_SIZE] for i in range(0, len(ciphertext_bytes), BLOCK_SIZE)]
    
    key_list = _key_scheduler(master_key, rounds, KEY_SIZE)
    decryption_keys = key_list[::-1]
    
    decrypted_blocks = []
    
    for block in text_blocks:
        decrypted_block = _decryption_engine(block, BLOCK_SIZE, decryption_keys)
        decrypted_blocks.append(decrypted_block)
        
    full_plaintext_bytes = b''.join(decrypted_blocks)
    
    try:
        unpadded_text = _unpad(full_plaintext_bytes, BLOCK_SIZE)
        
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")
    
    return unpadded_text.decode('utf-8')

if __name__ == "__main__":
    print("--- Feistel Cipher  ---")
    print("This program will encrypt the message and then decrypt it to verify the cipher.\n")

    TEST_MASTER_KEY = b'arsenics-very-very-secret-master-key.'
    ROUNDS = 16

    test_plaintext = input("Enter a message to encrypt: ")

    print("\n--- Encrypting ---")
    print(f"Original Text:  '{test_plaintext}'")
    encrypted_text = encrypt(test_plaintext, TEST_MASTER_KEY, ROUNDS)
    print(f"Encrypted Text: {encrypted_text}")

    print("\n--- Decrypting ---")
    try:
        decrypted_text = decrypt(encrypted_text, TEST_MASTER_KEY, ROUNDS)
        print(f"Decrypted Text: '{decrypted_text}'")

        assert test_plaintext == decrypted_text
        print("\nVerification Successful: The decrypted text matches the original.")

    except ValueError as e:
        print(f"\nAn error occurred during decryption: {e}")