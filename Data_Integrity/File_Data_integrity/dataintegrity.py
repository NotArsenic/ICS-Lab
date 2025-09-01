import hashlib
import os
from typing import Generator, Optional

def _read_data(file_path : str, chunk_size : int) -> Generator[bytes, None, None]:

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield data

def calculate_md5(file_path : str, chunk_size : int) -> Optional[str]:

    md5_hash = hashlib.md5()

    try:
        for chunk in _read_data(file_path, chunk_size):
            md5_hash.update(chunk)
            return md5_hash.hexdigest()
        
    except Exception as e:
            print(f"Error calculating MD5 hash: {e}")
            return None
        

def calculate_sha256(file_path : str, chunk_size : int) -> Optional[str]:

    sha256_hash = hashlib.sha256()

    try:
        for chunk in _read_data(file_path, chunk_size):
            sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        
    except Exception as e:
        print(f"Error calculating SHA-256 hash: {e}")
        return None


if __name__ == "__main__":

    chunk_size = 8192

    print(" ---- Data Integrity Check using SHA-256 & MD5 hashing algorithms ---- ")

    try:
        parent_dir = os.path.dirname(os.path.abspath(__file__))
    except:
        parent_dir = os.getcwd()

    input_folder_path = os.path.join(parent_dir, 'input')

    if not os.path.isdir(input_folder_path):
        print(f"Input folder path '{input_folder_path}' does not exist.")
        exit(1)

    input_files = [f for f in os.listdir(input_folder_path) if os.path.isfile(os.path.join(input_folder_path, f))]


    if len(input_files) == 0:
        print(f"No files found in the input folder path '{input_folder_path}'.")
        exit(1)
    
    if len(input_files) > 1:
        print(f"Multiple files found in the input folder, checking only the first file '{input_files[0]}'.")

    file = input_files[0]
    file_path = os.path.join(input_folder_path, file)
    
    inputcheck_folder_path = os.path.join(parent_dir, 'input_check')
    
    if not os.path.isdir(inputcheck_folder_path):
        raise Exception(f"Input check folder path '{inputcheck_folder_path}' does not exist.")
    if not os.path.isfile(os.path.join(inputcheck_folder_path, file)):
        raise Exception(f"File '{file}' not found in the input check folder path '{inputcheck_folder_path}'.")
    
    inputcheck_files = [f for f in os.listdir(inputcheck_folder_path) if os.path.isfile(os.path.join(inputcheck_folder_path, f))]
    
    if len(inputcheck_files) == 0:
        raise Exception(f"No files found in the input check folder path '{inputcheck_folder_path}'.")
    
    if len(inputcheck_files) > 1:
        print(f"Multiple files found in the input check folder, checking only the first file '{inputcheck_files[0]}'.")
        
    check_file = inputcheck_files[0]
    check_file_path = os.path.join(inputcheck_folder_path, check_file)
    

    print(f"\n\nChecking data integrity for file: {file} with respect to file: {check_file}\n")

    md5 = calculate_md5(file_path, chunk_size)
    sha256 = calculate_sha256(file_path, chunk_size)
    
    md5_check = calculate_md5(check_file_path, chunk_size)
    sha256_check = calculate_sha256(check_file_path, chunk_size)

    if md5 and sha256:
        print(f"MD5 Hash: {md5}")
        print(f"SHA-256 Hash: {sha256}")

    else: 
        print("Failed to compute hashes for input files.")
        exit(1)
        
    if md5_check and sha256_check:
        print(f"\nMD5 Hash (Check File): {md5_check}")
        print(f"SHA-256 Hash (Check File): {sha256_check}\n")
    else:
        print("Failed to compute hashes for check files.")
        exit(1)
    
    if md5 == md5_check and sha256 == sha256_check:
        print("MD5 Hashes match. Data integrity verified using MD5 & sha256.")
        
    
    else:
        print("MD5 Hashes do not match! Data integrity compromised using MD5 & sha256.")
        
    

