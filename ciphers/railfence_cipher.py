def idx_generator(rails, length):
    if rails <= 1:
        for _ in range(length):
            yield 0
        return

    current_rail = 0
    direction = 1

    for _ in range(length):
        yield current_rail

        if current_rail == 0:
            direction = 1
            
        elif current_rail == rails - 1:
            direction = -1

        current_rail += direction

def encrypt(plaintext : str, rails : int) -> str:
    if rails <= 1:
        return plaintext

    fence = [[] for _ in range(rails)]

    for char, rail_index in zip(plaintext, idx_generator(rails, len(plaintext))):
        fence[rail_index].append(char)

    encrypted_text =  "".join("".join(rail) for rail in fence)
    return encrypted_text


def decrypt(ciphertext : str, rails : int) -> str:
    if rails <= 1:
        return ciphertext

    fence_lengths = [0] * rails
    for rail_index in idx_generator(rails, len(ciphertext)):
        fence_lengths[rail_index] += 1

    fence = [[] for _ in range(rails)]
    cipher_iterator = iter(ciphertext)
    for i in range(rails):
        for _ in range(fence_lengths[i]):
            fence[i].append(next(cipher_iterator))

    plaintext = []
    for rail_index in idx_generator(rails, len(ciphertext)):
        plaintext.append(fence[rail_index].pop(0))

    return "".join(plaintext)

if __name__ == "__main__":
    print("Rail Fence Cipher Encryption/Decryption")
    print("This program performs encryption and decryption using the Rail Fence cipher.\n")

    test_plaintext = input("Enter text to encrypt: ")
    rails = int(input("Enter number of rails: "))

    encrypted_text = encrypt(test_plaintext, rails)
    print(f"Encrypted Text: {encrypted_text}")

    decrypted_text = decrypt(encrypted_text, rails)
    print(f"Decrypted Text: {decrypted_text}")