import random, secrets
from math import gcd

# -----------------------------
# Utilities
# -----------------------------

# Small primes for quick trial division
_small_primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
    251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
    397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
    463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
    619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
    701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773,
    787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
    863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997
]


# Miller–Rabin primality test
def _miller_rabin(n: int, bases=None) -> bool:
    if n < 2:
        return False
    for p in _small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # write n-1 = 2^r * d
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    if bases is None:
        bases = [2, 3, 5, 7, 11, 13, 17]
        if n.bit_length() > 64:  # add some random bases for bigger numbers
            bases = list(dict.fromkeys(bases + [secrets.randbelow(n - 3) + 2 for _ in range(5)]))
    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_probable_prime(n: int) -> bool:
    return _miller_rabin(n)


def random_prime(bits: int) -> int:
    """Optimized prime generator using wheel + trial division + MR."""
    wheel = 15015
    residues = [r for r in range(1, wheel, 2) if gcd(r, wheel) == 1]
    while True:
        base = secrets.randbits(bits - wheel.bit_length())
        candidate_base = base << wheel.bit_length()
        for r in residues:
            n = candidate_base + r
            n |= (1 << (bits - 1))  # ensure correct bit length
            if all(n % p != 0 for p in _small_primes):
                if is_probable_prime(n):
                    return n


def safe_prime(bits: int):
    """Generate safe prime p=2q+1 with q prime."""
    while True:
        q = random_prime(bits - 1)
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q


def find_generator(p: int, q: int) -> int:
    """Find generator g for group modulo safe prime p."""
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


# -----------------------------
# ElGamal
# -----------------------------
def elgamal_keygen(bits=32):
    p, q = safe_prime(bits)
    g = find_generator(p, q)
    x = secrets.randbelow(p - 2) + 1  # private key
    y = pow(g, x, p)  # public key
    return (p, g, y), x


def elgamal_encrypt(pub_key, m: int):
    p, g, y = pub_key
    assert 0 <= m < p
    k = secrets.randbelow(p - 2) + 1
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)


def elgamal_decrypt(priv_key, pub_key, ct):
    p, g, y = pub_key
    a, b = ct
    s = pow(a, priv_key, p)
    s_inv = pow(s, -1, p)
    return (b * s_inv) % p


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    pub, priv = elgamal_keygen(bits=32)  # try with 32 bits; increase to 64/128
    m = 2025 % pub[0]
    ct = elgamal_encrypt(pub, m)
    m2 = elgamal_decrypt(priv, pub, ct)
    print("Public key:", pub)
    print("Private key:", priv)
    print("Plaintext:", m)
    print("Ciphertext:", ct)
    print("Decrypted:", m2)
