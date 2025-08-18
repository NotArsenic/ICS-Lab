# Simple AES-like Cipher Implementation

import base64

# -- Global Constants --
S_BOX = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

INV_S_BOX = (
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE,
)

_GMUL_TABLE = (
    (0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0),
    (0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf),
    (0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x3, 0x1, 0x7, 0x5, 0xb, 0x9, 0xf, 0xd),
    (0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2),
    (0x0, 0x4, 0x8, 0xc, 0x3, 0x7, 0xb, 0xf, 0x6, 0x2, 0xe, 0xa, 0x5, 0x1, 0xd, 0x9),
    (0x0, 0x5, 0xa, 0xf, 0x7, 0x2, 0xd, 0x8, 0xe, 0xb, 0x4, 0x1, 0x9, 0xc, 0x3, 0x6),
    (0x0, 0x6, 0xc, 0xa, 0xb, 0xd, 0x7, 0x1, 0x5, 0x3, 0x9, 0xf, 0xe, 0x8, 0x2, 0x4),
    (0x0, 0x7, 0xe, 0x9, 0xf, 0x8, 0x1, 0x6, 0xd, 0xa, 0x3, 0x4, 0x2, 0x5, 0xc, 0xb),
    (0x0, 0x8, 0x3, 0xb, 0x6, 0xe, 0x5, 0xd, 0xc, 0x4, 0xf, 0x7, 0xa, 0x2, 0x9, 0x1),
    (0x0, 0x9, 0x1, 0x8, 0x2, 0xb, 0x3, 0xa, 0x4, 0xd, 0x5, 0xc, 0x6, 0xf, 0x7, 0xe),
    (0x0, 0xa, 0x7, 0xd, 0xe, 0x4, 0x9, 0x3, 0xf, 0x5, 0x8, 0x2, 0x1, 0xb, 0x6, 0xc),
    (0x0, 0xb, 0x5, 0xe, 0xa, 0x1, 0xf, 0x4, 0x7, 0xc, 0x2, 0x9, 0xd, 0x6, 0x8, 0x3),
    (0x0, 0xc, 0xb, 0x7, 0x5, 0x9, 0xe, 0x2, 0xa, 0x6, 0x1, 0xd, 0xf, 0x3, 0x4, 0x8),
    (0x0, 0xd, 0x9, 0x4, 0x1, 0xc, 0x8, 0x5, 0x2, 0xf, 0xb, 0x6, 0x3, 0xe, 0xa, 0x7),
    (0x0, 0xe, 0xf, 0x1, 0xd, 0x3, 0x2, 0xc, 0x9, 0x7, 0x6, 0x8, 0x4, 0xa, 0xb, 0x5),
    (0x0, 0xf, 0xd, 0x2, 0x9, 0x6, 0x4, 0xb, 0x1, 0xe, 0xc, 0x3, 0x8, 0x7, 0x5, 0xa),
)


# --- Utility Functions ---
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _gmultiply(a: int, b: int) -> int:
    return _GMUL_TABLE[a][b]

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

def _prepare_plaintext(plaintext : str, block_size : int) -> list[bytes]:
    plaintext_bytes = plaintext.encode('utf-8')
    padded_text = _pad(plaintext_bytes, block_size)
    
    blocks = [padded_text[i : i+block_size] for i in range(0, len(padded_text), block_size)]
    
    return blocks

# --- Key Scheduling Helpers---
def _rot_nib(byte_val : int) -> int:
   left_nibble = (byte_val & 0xF0) >> 4
   right_nibble = (byte_val & 0x0F) << 4
   return left_nibble | right_nibble

def _sub_nibble(nibble : int) -> int:
    return S_BOX[nibble]

def _rcon(i: int) -> int:
    if i == 1:
        return 0x80
    elif i == 2:
        return 0x30
    else:
        raise ValueError("RCON only supports values 1 or 2")
    
def _g_function(byte_data: int) -> int:
    
    rotated_byte = _rot_nib(byte_data)

    left_nibble = (rotated_byte & 0xF0) >> 4
    right_nibble = rotated_byte & 0x0F
    
    sub_left = _sub_nibble(left_nibble)
    sub_right = _sub_nibble(right_nibble)

    return (sub_left << 4) | sub_right
   
# --- Key Gen ---
def _key_scheduler(master_key : bytes) -> list[bytes]:
    words = [b''] * 6  
    words[0] = master_key[0:1]  
    words[1] = master_key[1:2]
    
    for i in range(2, 6, 2):
        prev_word_1 = words[i-2]
        prev_word_2 = words[i-1]
        
        g_out = _g_function(prev_word_2[0])
        
        round_n = i // 2
        rcon_val = _rcon(round_n)

        new_word1_val = prev_word_1[0] ^ rcon_val ^ g_out
        words[i] = bytes([new_word1_val])

        new_word2 = words[i][0] ^ prev_word_2[0]
        words[i+1] = bytes([new_word2])
        
        
    round_keys = []
    for i in range(0, len(words), 2):
        round_keys.append(words[i] + words[i+1])
    return round_keys


# --- ENCRYPTION ---
# --- Encryption helpers ---
def _sub_nibbles_state(state: bytes) -> bytes:
    new_bytes_list = []
    for byte_val in state:
        left_nibble = (byte_val & 0xF0) >> 4
        right_nibble = byte_val & 0x0F

        sub_left = _sub_nibble(left_nibble)
        sub_right = _sub_nibble(right_nibble)
        
        new_byte = (sub_left << 4) | sub_right
        new_bytes_list.append(new_byte)
    return bytes(new_bytes_list)

def _shift_rows(state : bytes) -> bytes:
    n0 = (state[0] & 0xF0) >> 4  
    n1 = state[0] & 0x0F         
    n2 = (state[1] & 0xF0) >> 4  
    n3 = state[1] & 0x0F         

    new_byte0 = (n0 << 4) | n3
    new_byte1 = (n2 << 4) | n1

    return bytes([new_byte0, new_byte1])

def _mix_columns(state : bytes) -> bytes:
    n0 = (state[0] & 0xF0) >> 4  
    n1 = state[0] & 0x0F         
    n2 = (state[1] & 0xF0) >> 4  
    n3 = state[1] & 0x0F         

    s00 = _gmultiply(1, n0) ^ _gmultiply(4, n1)
    s10 = _gmultiply(4, n0) ^ _gmultiply(1, n1)
    s01 = _gmultiply(1, n2) ^ _gmultiply(4, n3)
    s11 = _gmultiply(4, n2) ^ _gmultiply(1, n3)
    
    new_byte0 = (s00 << 4) | s10
    new_byte1 = (s01 << 4) | s11       
    
    return bytes([new_byte0, new_byte1])

        
def _encryption_engine(initial_state : bytes, round_keys : list[bytes]) -> bytes:

    state = _sub_nibbles_state(initial_state)
    state = _shift_rows(state)
    state = _mix_columns(state)
    state = _xor(state, round_keys[1]) 

    state = _sub_nibbles_state(state)
    state = _shift_rows(state)
    state = _xor(state, round_keys[2])

    return state



# --- DECRYPTION ---
# --- Decryption helpers ---
def _inv_sub_nibbles_state(state: bytes) -> bytes:
    new_bytes_list = []
    for byte_val in state:
        left_nibble = (byte_val & 0xF0) >> 4
        right_nibble = byte_val & 0x0F

        sub_left = INV_S_BOX[left_nibble]
        sub_right = INV_S_BOX[right_nibble]
        
        new_byte = (sub_left << 4) | sub_right
        new_bytes_list.append(new_byte)
    return bytes(new_bytes_list)


def _inv_shift_rows(state : bytes) -> bytes:
    n0 = (state[0] & 0xF0) >> 4
    n1 = state[0] & 0x0F
    n2 = (state[1] & 0xF0) >> 4
    n3 = state[1] & 0x0F     

    new_byte0 = (n0 << 4) | n3
    new_byte1 = (n2 << 4) | n1

    return bytes([new_byte0, new_byte1])


def _inv_mix_columns(state : bytes) -> bytes:
    n0 = (state[0] & 0xF0) >> 4  
    n1 = state[0] & 0x0F         
    n2 = (state[1] & 0xF0) >> 4  
    n3 = state[1] & 0x0F         

    s00 = _gmultiply(9, n0) ^ _gmultiply(2, n1)
    s10 = _gmultiply(2, n0) ^ _gmultiply(9, n1)
    s01 = _gmultiply(9, n2) ^ _gmultiply(2, n3)
    s11 = _gmultiply(2, n2) ^ _gmultiply(9, n3)
    
    new_byte0 = (s00 << 4) | s10
    new_byte1 = (s01 << 4) | s11       
    
    return bytes([new_byte0, new_byte1])


def _decryption_engine(state : bytes, round_keys : list[bytes]) -> bytes:
    
    state = _inv_shift_rows(state)
    state = _inv_sub_nibbles_state(state)
    state = _xor(state, round_keys[1]) 
    
    state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_nibbles_state(state)
    
    return state
    

# --- Main Functions ---
def encrypt(plaintext : str, master_key : bytes) -> str:
    
    BLOCK_SIZE = 2
    
    text_blocks = _prepare_plaintext(plaintext, BLOCK_SIZE)
    
    key_list = _key_scheduler(master_key)

    encrypted_blocks = []
    
    for block in text_blocks:    
        innit_block_with_key = _xor(block, key_list[0])
        encrypted_block = _encryption_engine(innit_block_with_key, key_list)
        encrypted_blocks.append(encrypted_block)
 
    encrypted_text_bytes = b''.join(encrypted_blocks)
    return base64.b64encode(encrypted_text_bytes).decode('utf-8')


def decrypt(ciphertext : str, master_key : bytes) -> str:
    BLOCK_SIZE = 2
    
    key_list = _key_scheduler(master_key)
    decryption_keys = key_list[::-1]
    
    try:
        ciphertext_bytes = base64.b64decode(ciphertext)
    except Exception as e:
        raise ValueError("Invalid Base64 encoded ciphertext") from e
    
    if len(ciphertext_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length is not a multiple of block size")
    
    text_blocks = [ciphertext_bytes[i : i+BLOCK_SIZE] for i in range(0, len(ciphertext_bytes), BLOCK_SIZE)]
    
    decrypted_blocks = []
    
    for block in text_blocks:
        state = _xor(block, decryption_keys[0]) 
        state = _decryption_engine(state, decryption_keys)
        state = _xor(state, decryption_keys[2]) 
        decrypted_blocks.append(state)
        
    full_plaintext_bytes = b''.join(decrypted_blocks)
    
    try:
        unpadded_text = _unpad(full_plaintext_bytes, BLOCK_SIZE)
        
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")
    
    return unpadded_text.decode('utf-8')


# --- Testing ---
if __name__ == "__main__":
    print("--- S-AES Implementation ---")
    print("This program will encrypt a message and then decrypt it to verify the cipher.\n")

    TEST_MASTER_KEY = b'\x2b\x7e' 

    test_plaintext = input("Enter a message to encrypt: ")

    print("\n--- Encrypting ---")
    print(f"Original Text:  '{test_plaintext}'")
    encrypted_text = encrypt(test_plaintext, TEST_MASTER_KEY)
    print(f"Encrypted Text: {encrypted_text}")

    print("\n--- Decrypting ---")
    try:
        decrypted_text = decrypt(encrypted_text, TEST_MASTER_KEY)
        print(f"Decrypted Text: '{decrypted_text}'")

        assert test_plaintext == decrypted_text
        print("\n Verification Successful: The decrypted text matches the original.")

    except ValueError as e:
        print(f"\n An error occurred during decryption: {e}")