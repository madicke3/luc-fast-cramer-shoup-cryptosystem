import random
import hashlib
from sympy import primerange


# Variable initialization for keyGen
p = 227
P = 23
Q = 1

print("la valeur de p est : ", p)

# Direct computation of Lucas sequences for V
def lucas_mod(n, P, Q, p):
    V0 = 2
    V1 = P

    if n == 0:
        return V0 % p
    elif n == 1:
        return V1 % p

    for i in range(2, n + 1):
        V2 = (P * V1 - Q * V0) % p
        V0, V1 = V1, V2

    return V1


# Utility function to generate a random prime number within a range
def generate_random_prime(min_value, max_value, exclude=[]):
    primes = list(primerange(min_value, max_value))
    primes = [prime for prime in primes if prime not in exclude]
    return random.choice(primes)


# Updated Key generation algorithm using lucas_V
def generate_keys(min_prime, max_prime):
    # Step 1: Choose a prime p and initial values P1 and Q=1

    # Step 2: Choose random prime elements (k, q, x, y) in F_{p^2}^*
    k = generate_random_prime(min_prime, max_prime, exclude=[p, P])

    print("la valeur de k = ", k)

    # Ensure q has a bit size of half of p
    p_bits = p.bit_length()
    q_bits = p_bits // 2
    q_min = 1 << (q_bits - 1)
    q_max = (1 << q_bits) - 1

    # Generate random prime q within the bit size constraint
    q_candidates = [q for q in primerange(q_min, q_max + 1) if q not in [p, P, k]]

    q = random.choice(q_candidates)
    x = generate_random_prime(min_prime, max_prime, exclude=[p, P, k, q])
    y = generate_random_prime(min_prime, max_prime, exclude=[p, P, k, q, x])

    # Calculate s' and t such that kp = qs' + t
    s_prime = (k * p) // q
    t = (k * p) % q

    # Ensure t meets the bit size constraint
    if t.bit_length() > q.bit_length():
        raise ValueError("t does not meet the bit size constraint.")

    # Calculate s in Z_p
    s = s_prime % p

    print("la vleur de s= ", s)

    # Compute b, c, d, h
    b = lucas_mod(s, P, Q, p)
    sx = (s * x) % p
    c = lucas_mod(sx, P, Q, p)
    sy = (s * y) % p
    d = lucas_mod(sy, P, Q, p)
    h = lucas_mod(t, P, Q, p)

    # Step 3: Choose a hash function H
    H = hashlib.sha256

    # Private key
    sk = (q, t, x, y)

    # Public key
    pk = (P, b, c, d, h, H)

    return sk, pk


# Hash function
def hash_function(*args):
    # Concatenate all arguments and hash them using SHA-256
    hash_input = ''.join(map(str, args)).encode()
    return int(hashlib.sha256(hash_input).hexdigest(), 16)


# Encryption algorithm
def encrypt_message(pk):
    m = 73

    print("le message initial est m = ", m)

    # Step 1: Choose a secret number r
    r = random.randint(1, p)
    # Step 2: Compute u1, u2, G, e, alpha, v
    u1 = lucas_mod(r, pk[1], Q, p)
    u2 = lucas_mod(r, pk[0], Q, p)
    G = lucas_mod(r, pk[4], Q, p)
    e = (G * m) % p
    alpha = hash_function(u1, u2, e) % p
    v1 = lucas_mod(r, pk[2], Q, p)
    r_alpha = r * alpha
    r_alpha_mod = r_alpha % p
    v2 = lucas_mod(r_alpha_mod, pk[3], Q, p)
    v = (v1 * v2) % p
    ciphertext = (u1, u2, e, v)
    return ciphertext


# Decryption algorithm
def decrypt_message(sk, ciphertext):
    alpha = hash_function(ciphertext[0], ciphertext[1], ciphertext[2]) % p
    w = lucas_mod(sk[0], ciphertext[0], Q, p)
    v_t = lucas_mod(sk[1], ciphertext[1], Q, p)
    condition1 = (w * v_t) % p
    v_x = lucas_mod(sk[2], ciphertext[0], Q, p)
    yalpha = (sk[3] * alpha) % p
    v_yalpha = lucas_mod(yalpha, ciphertext[0], Q, p)
    condition2 = (v_x * v_yalpha) % p

    if condition1 == 1 and condition2 == ciphertext[3]:
        m = (w * ciphertext[2]) % p
        return m
    else:
        print("m: ", (w * ciphertext[2]) % p)
        return None


# Loop to run the key generation and encryption/decryption multiple times over 1 minute
import time
end_time = time.time() + 1 * 60  # 1 minute from now
while time.time() < end_time:
    # Key generation
    private_key, public_key = generate_keys(2, p)
    sk = private_key
    pk = public_key

    print("Private Key: (q, t, x, y)= ", sk)
    print("Public Key: (P, b, c, d, h, H)= ", pk)

    # Encryption
    ciphertext = encrypt_message(pk)
    print("le message chiffré est: (u1, u2, e, v)= ", ciphertext)

    # Decryption
    plaintext = decrypt_message(sk, ciphertext)
    print("le message déchiffré est : ", plaintext)

    print("--------------------------------------------------------------------")

    # Wait for a short period before the next iteration
    time.sleep(5)  # Adjust the sleep time if needed

print("Finished running the test for 1 minute.")
