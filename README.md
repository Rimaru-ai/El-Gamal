# ElGamal Cryptosystem with Optimized Safe Prime Generation

This project implements the **ElGamal public-key cryptosystem** using **safe primes (Sophie Germain primes)**.  
It includes an optimized prime generation routine that uses:
- Trial division by small primes.
- Wheel factorization (skip obvious composites).
- Miller–Rabin primality test with deterministic/random bases.
- Cryptographic randomness (`secrets` module).

The implementation demonstrates **key generation, encryption, and decryption**, along with faster prime generation compared to a naïve approach.

---

## 🚀 Features
- Safe prime generation (`p = 2q + 1` with `q` prime).
- Efficient Miller–Rabin primality testing.
- Secure ElGamal encryption & decryption.
- Works with small primes for testing (e.g. 32–64 bits).
- Scales to larger primes (e.g. 1024+ bits), though runtime increases.

---

## 📂 Files
- `elgamal.py` → Main implementation (safe primes + ElGamal).
- `README.md` → Project overview & usage.
- `requirements.txt` → Required dependencies.

---

## ⚡ Usage
### Run Example
```bash
python elgamal.py
