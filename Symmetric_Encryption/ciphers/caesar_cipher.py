def encrypt(plaintext : str, shift : int) -> str:
    ciphertext = ""

    if(shift < 0):
        shift = 26 + (shift % 26)

    if(shift == 0):
        return plaintext

    if(shift > 26):
        shift = shift % 26

    if(plaintext == ""):
        return ciphertext

    for char in plaintext:

        if char.isalpha():

            if char.isupper():
                ciphertext += chr((ord(char) + shift - 65) % 26 + 65)

            else:
                ciphertext += chr((ord(char) + shift - 97) % 26 + 97)

        else:
            ciphertext += char

    return ciphertext


def decrypt(ciphertext : str, shift : int) -> str:
    plaintext = encrypt(ciphertext, -shift)
    return plaintext


if __name__ == "__main__":
    
    print("Caesar Cipher Encryption/Decryption")
    print("This program performs encryption and decryption text using the Caesar cipher.\n")
    
    test_plaintext = input("Enter text to encrypt: ")
    
    shift_value = int(input("Enter shift value (0-25): "))
    
    encrypted_text = encrypt(test_plaintext, shift_value)
    print(f"Encrypted Text: {encrypted_text}")

    decrypted_text = decrypt(encrypted_text, shift_value)
    print(f"Decrypted Text: {decrypted_text}")