import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sym_ciphers import caesar_cipher
from sym_ciphers import railfence_cipher
from sym_ciphers import feistel_cipher
from sym_ciphers import simple_aes_cipher

import socket
import threading
import secrets

HOST = '127.0.0.1'
PORT = 60006


def send_messages(client_socket : socket.socket):
    while True:
        print("\n\n[CLIENT] This is the Symmetric Encryption Client.")
        
        message = input("[CLIENT] Enter your message: ")
        
        print("[CLIENT] Select the cipher to use:")
        print("1. Caesar Cipher")
        print("2. Rail Fence Cipher")
        print("3. Feistel Cipher")
        print("4. Simple AES Cipher")
        
        cipher_choice = input("[CLIENT] Enter your choice (1-4): ")
        
        key = None
        encrypted_message = ""
        
        match cipher_choice:
            case '1':
                print("[CLIENT] Using Caesar Cipher.")
                
                print("Press 1 to use a random key , or 2 to enter a custom key.")
                key_choice = input("[CLIENT] Enter your choice (1-2): ")
                if key_choice == '1':
                    key = secrets.randbits(8)
                    print(f"[CLIENT] Random key generated: {key}")
                elif key_choice == '2':
                    key = int(input("[CLIENT] Enter custom key value : "))
                else:
                    key = secrets.randbits(8)
                    print(f"[CLIENT] Invalid choice. Defaulting to random key. Generated key : {key}")
                    
                encrypted_message = caesar_cipher.encrypt(message, key)

                data_out = str(cipher_choice) + ' | ' + encrypted_message + ' | ' + str(key)
                client_socket.sendall(data_out.encode('utf-8'))
                
            case '2':
                print("[CLIENT] Using Rail Fence Cipher.")
                
                print("Press 1 to use a random key, or 2 to enter a custom key.")
                key_choice = input("[CLIENT] Enter your choice (1-2): ")
                if key_choice == '1':
                    key = secrets.randbelow(8) + 2 
                    print(f"[CLIENT] Random key value generated: {key}")
                elif key_choice == '2':
                    key = int(input("[CLIENT] Enter custom key value : "))
                else:
                    key = secrets.randbelow(8) + 2 
                    print(f"[CLIENT] Invalid choice. Defaulting to random key. Generated key : {key}")
            
                encrypted_message = railfence_cipher.encrypt(message, key)
                
                data_out = str(cipher_choice) + ' | ' + encrypted_message + ' | ' + str(key)
                client_socket.sendall(data_out.encode('utf-8'))
                
            case '3':
                print("[CLIENT] Using Feistel Cipher.")
                
                print("Press 1 to use a random key, or 2 to enter a custom key.")
                key_choice = input("[CLIENT] Enter your choice (1-2): ")
                if key_choice == '1':
                    key = secrets.token_bytes(16)
                    print(f"[CLIENT] Random key value generated: {key}")
                elif key_choice == '2':
                    key_str = input("[CLIENT] Enter custom key: ")
                    key = key_str.encode('utf-8')
                else:
                    key = secrets.token_bytes(16)
                    print(f"[CLIENT] Invalid choice. Defaulting to random key. Generated key : {key}")
                    
                rounds = int(input("[CLIENT] Enter number of rounds : ") or 16)
                encrypted_message = feistel_cipher.encrypt(message, key, rounds)
                
                data_out = str(cipher_choice) + ' | ' + encrypted_message + ' | ' + key.hex()
                client_socket.sendall(data_out.encode('utf-8'))
                
            case '4':
                print("[CLIENT] Using Simple AES Cipher.")
                
                key_choice = input("[CLIENT] Enter your choice (1-2): ")
                if key_choice == '1':
                    key = secrets.token_bytes(2)
                    print(f"[CLIENT] Random key value generated: {key}")
                elif key_choice == '2':
                    key_str = input("[CLIENT] Enter custom key: ")
                    key = key_str.encode('utf-8')
                else:
                    key = secrets.token_bytes(2)
                    print(f"[CLIENT] Invalid choice. Defaulting to random key. Generated key : {key}")
                    
                encrypted_message = simple_aes_cipher.encrypt(message, key)
                
                data_out = str(cipher_choice) + ' | ' + encrypted_message + ' | ' + key.hex()
                client_socket.sendall(data_out.encode('utf-8'))
                
            case _:
                print("[CLIENT] Invalid choice. Please try again.")
                continue
        
def receive_messages(client_socket : socket.socket):
    while True:
        try:
            data_in = client_socket.recv(1024)
            if not data_in:
                print("[CLIENT] Connection closed by the server.")
                break
            
            decrypted_data = data_in.decode('utf-8')

            print(f"\n\nReceived message from the server")
            
            try:
                cipher_id, encrypted_message, key = decrypted_data.split(' | ')
                
                key = int(key) if cipher_id == '1' else bytes.fromhex(key)
                
                cipher_name = ""

                match cipher_id:
                    case '1':
                        cipher_name = "Caesar Cipher"
                        decrypted_message = caesar_cipher.decrypt(encrypted_message, key)
                        
                    case '2':
                        cipher_name = "Rail Fence Cipher"
                        decrypted_message = railfence_cipher.decrypt(encrypted_message, key)
                        
                    case '3':
                        
                        cipher_name = "Feistel Cipher"
                        decrypted_message = feistel_cipher.decrypt(encrypted_message, key, 16)
                    case '4':
                        
                        cipher_name = "Simple AES Cipher"
                        decrypted_message = simple_aes_cipher.decrypt(encrypted_message, key)
                        
                    case _:
                        print("[CLIENT] Invalid cipher ID received.")
                        continue   
                    
                print(f"[SERVER] Decrypted message: {decrypted_message} ")
                print(f"[SERVER] cipher used: {cipher_name}")
            
            except ValueError:
                print(f"\n[CLIENT] Received malformed data: {decrypted_data}")    
                        
        except Exception as e:
            print(f"[CLIENT] Error receiving data: {e}")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((HOST, PORT))
        print("Connected to the server.")
        print("[SYSTEM] Welcome to the Symmetric Encryption Client!")
        print("[SYSTEM] Starting threads.\n")
        
    except ConnectionRefusedError:
        print("[SYSTEM] Connection failed.")
        return
    
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()
    
    send_messages(client_socket)
    
    
if __name__ == "__main__":
    start_client()