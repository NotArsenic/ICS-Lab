import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sym_ciphers import caesar_cipher
from sym_ciphers import railfence_cipher
from sym_ciphers import feistel_cipher
from sym_ciphers import simple_aes_cipher

import socket
import threading
from datetime import datetime
import time

HOST = '127.0.0.1'
PORT = 60006

def log_message(filename: str, content: str):
    """Appends a timestamped message to a specified log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {content}\n")
    except IOError as e:
        print(f"[SERVER-ERROR] Could not write to log file {filename}: {e}")

def broadcast(message: bytes, sender_socket: socket.socket, clients: list, lock: threading.Lock):
    """Sends a message to all clients except the sender."""
    with lock:
        for client in clients[:]:
            if client != sender_socket:
                try:
                    client.sendall(message)
                except socket.error:
                    print(f"[SERVER] Client {client.getpeername()} seems to be disconnected. Removing.")
                    clients.remove(client)

def handle_client(client_socket: socket.socket, clients: list, lock: threading.Lock):
    """Handles all communication for a single client connection."""
    client_address = client_socket.getpeername()
    client_id = f"Client-{client_address[1]}" 

    while True:
        try:
            data_in = client_socket.recv(1024)
            if not data_in:
                print(f"[SERVER] {client_id} disconnected cleanly.")
                break

            broadcast(data_in, client_socket, clients, lock)

            message_str = data_in.decode('utf-8')
            log_message("encrypted_log.txt", f"{client_id}: {message_str}")

            try:
                cipher_id, key_str, encrypted_message = message_str.split('|', 2)
                
                decrypted_message = ""
                
                match cipher_id:
                    case '1':
                        key = int(key_str)
                        decrypted_message = caesar_cipher.decrypt(encrypted_message, key)
                    case '2':
                        key = int(key_str)
                        decrypted_message = railfence_cipher.decrypt(encrypted_message, key)
                    case '3':
                        key = bytes.fromhex(key_str)
                        rounds = 16
                        decrypted_message = feistel_cipher.decrypt(encrypted_message, key, rounds)
                    case '4':
                        key = bytes.fromhex(key_str)
                        decrypted_message = simple_aes_cipher.decrypt(encrypted_message, key)
                    case _:
                        decrypted_message = "[ERROR: Unknown Cipher ID]"

                log_message("decrypted_log.txt", f"{client_id}: {decrypted_message}")

            except (ValueError, TypeError) as e:
                log_message("decrypted_log.txt", f"{client_id}: [DECRYPTION-ERROR] {e}")

        except ConnectionResetError:
            print(f"[SERVER] {client_id} disconnected abruptly.")
            break
        except Exception as e:
            print(f"[SERVER-ERROR] Error with {client_id}: {e}")
            break
    
    with lock:
        clients.remove(client_socket)
    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(2)
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    clients = []
    lock = threading.Lock()
    
    while len(clients) < 2:
        print("[SERVER] Waiting for a connection...")
        client_socket, addr = server_socket.accept()
        
        with lock:
            clients.append(client_socket)
        
        print(f"[SERVER] Accepted connection from {addr}")
        
        thread = threading.Thread(target=handle_client, args=(client_socket, clients, lock))
        thread.daemon = True
        thread.start()
        
    print(f"[SERVER] Two clients connected. The chat is now live!\n")

    while True:
        time.sleep(1)

if __name__ == "__main__":
    start_server()
