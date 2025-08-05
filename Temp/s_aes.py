

S_BOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

INV_S_BOX = {
    0x9: 0x0, 0x4: 0x1, 0xA: 0x2, 0xB: 0x3,
    0xD: 0x4, 0x1: 0x5, 0x8: 0x6, 0x5: 0x7,
    0x6: 0x8, 0x2: 0x9, 0x0: 0xA, 0x3: 0xB,
    0xC: 0xC, 0xE: 0xD, 0xF: 0xE, 0x7: 0xF
}

RCON_1 = 0x80
RCON_2 = 0x30

def int_to_16_bit_binary(n):
    return format(n, '016b')

def int_to_8_bit_binary(n):
    return format(n, '08b')

def binary_to_int(b):
    return int(b, 2)

def substitute_nibbles(nibbles, sbox):
    n0 = nibbles >> 12
    n1 = (nibbles >> 8) & 0b1111
    n2 = (nibbles >> 4) & 0b1111
    n3 = nibbles & 0b1111

    sub_n0 = sbox[n0]
    sub_n1 = sbox[n1]
    sub_n2 = sbox[n2]
    sub_n3 = sbox[n3]

    return (sub_n0 << 12) | (sub_n1 << 8) | (sub_n2 << 4) | sub_n3

def shift_rows(state):
    n0 = state >> 12
    n1 = (state >> 8) & 0b1111
    n2 = (state >> 4) & 0b1111
    n3 = state & 0b1111

    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1

def gf_multiply(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a

        hi_bit_set = a & 0b1000
        a <<= 1

        if hi_bit_set:
            a ^= 19

        b >>= 1
    return p & 0b1111

def mix_columns(state):
    s00 = state >> 12
    s10 = (state >> 8) & 0b1111
    s01 = (state >> 4) & 0b1111
    s11 = state & 0b1111

    s00_prime = gf_multiply(1, s00) ^ gf_multiply(4, s10)
    s10_prime = gf_multiply(4, s00) ^ gf_multiply(1, s10)
    s01_prime = gf_multiply(1, s01) ^ gf_multiply(4, s11)
    s11_prime = gf_multiply(4, s01) ^ gf_multiply(1, s11)

    return (s00_prime << 12) | (s10_prime << 8) | (s01_prime << 4) | s11_prime

def inv_mix_columns(state):
    s00 = state >> 12
    s10 = (state >> 8) & 0b1111
    s01 = (state >> 4) & 0b1111
    s11 = state & 0b1111

    s00_prime = gf_multiply(9, s00) ^ gf_multiply(2, s10)
    s10_prime = gf_multiply(2, s00) ^ gf_multiply(9, s10)
    s01_prime = gf_multiply(9, s01) ^ gf_multiply(2, s11)
    s11_prime = gf_multiply(2, s01) ^ gf_multiply(9, s11)

    return (s00_prime << 12) | (s10_prime << 8) | (s01_prime << 4) | s11_prime

def add_round_key(state, key):
    return state ^ key

def g_function(word, rcon):
    n0 = word >> 4
    n1 = word & 0b1111
    rotated_word = (n1 << 4) | n0

    sub_n0 = S_BOX[rotated_word >> 4]
    sub_n1 = S_BOX[rotated_word & 0b1111]
    substituted_word = (sub_n0 << 4) | sub_n1

    return substituted_word ^ rcon

def generate_round_keys(key):
    k0 = key

    w0 = key >> 8
    w1 = key & 0xFF

    g_of_w1 = g_function(w1, RCON_1 >> 8)
    w2 = w0 ^ g_of_w1
    w3 = w2 ^ w1

    k1 = (w2 << 8) | w3

    g_of_w3 = g_function(w3, RCON_2 >> 8)
    w4 = w2 ^ g_of_w3
    w5 = w4 ^ w3

    k2 = (w4 << 8) | w5

    return k0, k1, k2

def encrypt(plaintext_int, key_int):
    print("- ENCRYPTION PROCESS -")

    #  Key Expansion
    k0, k1, k2 = generate_round_keys(key_int)
    print(f"Initial Plaintext: {int_to_16_bit_binary(plaintext_int)}")
    print(f"Initial Key (K0):  {int_to_16_bit_binary(k0)}")
    print(f"Round Key 1 (K1):  {int_to_16_bit_binary(k1)}")
    print(f"Round Key 2 (K2):  {int_to_16_bit_binary(k2)}\n")

    state = add_round_key(plaintext_int, k0)
    print(f"After AddRoundKey(K0): {int_to_16_bit_binary(state)}")

    #  ROUND 1
    print("\n--- Round 1 ---")
    #  Substitute Nibbles
    state = substitute_nibbles(state, S_BOX)
    print(f"After SubNibbles:    {int_to_16_bit_binary(state)}")

    #  Shift Rows
    state = shift_rows(state)
    print(f"After ShiftRows:     {int_to_16_bit_binary(state)}")

    #  Mix Columns
    state = mix_columns(state)
    print(f"After MixColumns:    {int_to_16_bit_binary(state)}")

    #  Add Round Key 1
    state = add_round_key(state, k1)
    print(f"After AddRoundKey(K1): {int_to_16_bit_binary(state)}")

    #  ROUND 2
    print("\n--- Round 2 ---")
    #  Substitute Nibbles
    state = substitute_nibbles(state, S_BOX)
    print(f"After SubNibbles:    {int_to_16_bit_binary(state)}")

    #  Shift Rows
    state = shift_rows(state)
    print(f"After ShiftRows:     {int_to_16_bit_binary(state)}")

    #  Add Round Key 2
    state = add_round_key(state, k2)
    print(f"After AddRoundKey(K2): {int_to_16_bit_binary(state)}")

    ciphertext = state
    print(f"\nFinal Ciphertext: {int_to_16_bit_binary(ciphertext)}")
    return ciphertext

def decrypt(ciphertext_int, key_int):
    print("\n\n DECRYPTION ")

    k0, k1, k2 = generate_round_keys(key_int)
    print(f"Initial Ciphertext: {int_to_16_bit_binary(ciphertext_int)}")
    print(f"Initial Key (K0):   {int_to_16_bit_binary(k0)}")
    print(f"Round Key 1 (K1):   {int_to_16_bit_binary(k1)}")
    print(f"Round Key 2 (K2):   {int_to_16_bit_binary(k2)}\n")

    state = add_round_key(ciphertext_int, k2)
    print(f"After AddRoundKey(K2):  {int_to_16_bit_binary(state)}")

    #  ROUND 1
    print("\n--- Inverse Round 1 ---")
    #  Inverse Shift Rows
    state = shift_rows(state)
    print(f"After InvShiftRows:     {int_to_16_bit_binary(state)}")

    #  Inverse Substitute Nibbles
    state = substitute_nibbles(state, INV_S_BOX)
    print(f"After InvSubNibbles:    {int_to_16_bit_binary(state)}")

    #  Add Round Key 1
    state = add_round_key(state, k1)
    print(f"After AddRoundKey(K1):  {int_to_16_bit_binary(state)}")

    #  Inverse Mix Columns
    state = inv_mix_columns(state)
    print(f"After InvMixColumns:    {int_to_16_bit_binary(state)}")

    #  ROUND 2
    print("\n--- Inverse Round 2 ---")
    #  Inverse Shift Rows
    state = shift_rows(state)
    print(f"After InvShiftRows:     {int_to_16_bit_binary(state)}")

    #  Inverse Substitute Nibbles
    state = substitute_nibbles(state, INV_S_BOX)
    print(f"After InvSubNibbles:    {int_to_16_bit_binary(state)}")

    #  Add Round Key 0
    state = add_round_key(state, k0)
    print(f"After AddRoundKey(K0):  {int_to_16_bit_binary(state)}")

    plaintext = state
    print(f"\nFinal Decrypted Plaintext: {int_to_16_bit_binary(plaintext)}")
    return plaintext

if __name__ == "__main__":
    example_plaintext = 0xD728
    example_key = 0x4AF5

    encrypted_text = encrypt(example_plaintext, example_key)

    decrypted_text = decrypt(encrypted_text, example_key)

    print("\n\n--- FINAL VERIFICATION ---")
    print(f"Original Plaintext: {int_to_16_bit_binary(example_plaintext)}")
    print(f"Decrypted Plaintext: {int_to_16_bit_binary(decrypted_text)}")

    if example_plaintext == decrypted_text:
        print("Success ")
    else:
        print("Failure ")

