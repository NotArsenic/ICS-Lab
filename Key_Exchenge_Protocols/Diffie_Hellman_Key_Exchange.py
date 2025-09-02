# Diffie Hellman Key Exchange Algorithm Implementation

import secrets
import math
from typing import Optional

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

def generate_prime(bit_size : int) -> int:
    """ Generate a prime number of specified bit size """
    
    if bit_size < 2:
        raise ValueError("Bit size must be at least 2")
    
    while True:
        num = secrets.randbits(bit_size) | (1 << (bit_size - 1)) | 1
        
        if _is_prime(num):
            return num

def generate_private_key(prime : int) -> int:
    """ Generate private key """
    
    if prime < 5:
        raise ValueError("Prime must be at least 5 to generate a valid private key")
    
    return secrets.randbelow(prime - 3) + 2

def _find_primitive_root(prime : int) -> int:
    """ Find a primitive root for prime number """

    if prime == 2:
        return 1

    phi = prime - 1
    factors = set()

    n = phi

    for i in range(2, math.isqrt(n) + 1):
        while n % i == 0:
            factors.add(i)
            n //= i
    if n > 1:
        factors.add(n)

    for g in range(2, prime):
        is_primitive_root = True
        for factor in factors:
            if pow(g, phi // factor, prime) == 1:
                is_primitive_root = False
                break
        if is_primitive_root:
            return g
    raise ValueError(f"No primitive root found for prime {prime}")


def _calculate_public_key(private_key : int, prime : int, primitive_root : int) -> int:
    """ Calculate public key using private key, prime and primitive root """
    return pow(primitive_root, private_key, prime)

def _calulate_shared_secret(op_public_key : int, private_key : int, prime : int) -> int:
    """ Calculate shared secret using other party's public key, own private key and prime """
    return pow(op_public_key, private_key, prime)

# --- Diffie-Hellman Key Exchange ---
def diffie_hellman_key_exchange(bit_size : int = 2048, prime : Optional[int] = None, primitive_root : Optional[int] = None) -> dict:
    """ Perform Diffie-Hellman Key Exchange and return shared secret keys for both parties """
    
    if prime is not None and primitive_root is not None:
        if not _is_prime(prime):
            raise ValueError("Provided prime is not a prime number")
        if pow(primitive_root, prime - 1, prime) != 1:
            raise ValueError("Provided root is not a valid primitive root for the given prime")

    if prime is None or primitive_root is None:
        prime = generate_prime(bit_size)
        primitive_root = _find_primitive_root(prime)

    private_key_A = generate_private_key(prime)
    private_key_B = generate_private_key(prime)
    
    public_key_A = _calculate_public_key(private_key_A, prime, primitive_root)
    public_key_B = _calculate_public_key(private_key_B, prime, primitive_root)
    
    shared_secret_A = _calulate_shared_secret(public_key_B, private_key_A, prime)
    shared_secret_B = _calulate_shared_secret(public_key_A, private_key_B, prime)
    
    assert shared_secret_A == shared_secret_B, "Shared secrets do not match!"
    print("Shared secrets calculated successfully and they match.")
    
    return {
        "prime": prime,
        "primitive_root": primitive_root,
        "A_private_key": private_key_A,
        "B_private_key": private_key_B,
        "A_public_key": public_key_A,
        "B_public_key": public_key_B,
        "shared_secret": shared_secret_A
    }


# --- Testing ---
if __name__ == "__main__":
    
    TEST_BIT_SIZE = 512
    
    print("\n--- Diffie-Hellman Key Exchange ---")
    print(f"Generating parameters with bit size: {TEST_BIT_SIZE}")

    choice = input("Do you want to provide a custom prime and primitive root? (y/n): ").lower()
    
    if choice == 'y':
        try:
            custom_prime = int(input("Enter a prime number (e.g., 23): "))
            custom_root = int(input(f"Enter a primitive root for {custom_prime} (e.g., 5): "))
            results = diffie_hellman_key_exchange(prime=custom_prime, primitive_root=custom_root)
        except (ValueError, TypeError) as e:
            print(f"Error: Invalid input. {e}")
            
    else:
        TEST_BIT_SIZE = 32
        print(f"\nGenerating new parameters with bit size: {TEST_BIT_SIZE}")
        results = diffie_hellman_key_exchange(bit_size=TEST_BIT_SIZE)

    print(f"Prime (p): {results['prime']}")
    print(f"Primitive Root (g): {results['primitive_root']}")
    print("-" * 40)

    print(f"A's Private Key (a): {results['A_private_key']}")
    print(f"B's Private Key (b): {results['B_private_key']}")
    print("-" * 40)

    print(f"A's Public Key (A): {results['A_public_key']}")
    print(f"B's Public Key (B): {results['B_public_key']}")
    print("-" * 40)

    print(f"Shared Secret (s): {results['shared_secret']}")
    print("--- Success! Both parties have the same secret. ---")

