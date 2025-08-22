# app.py
import json
import ast
import secrets
import streamlit as st
from math import gcd

# -----------------------------
# Primes & ElGamal (optimized)
# -----------------------------
_SMALL_PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def _miller_rabin(n: int, k=7) -> bool:
    if n < 2: return False
    for p in _SMALL_PRIMES:
        if n == p: return True
        if n % p == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
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

def _random_prime(bits: int) -> int:
    wheel = 15015
    residues = [r for r in range(1, wheel, 2) if gcd(r, wheel) == 1]
    while True:
        base = secrets.randbits(bits - wheel.bit_length())
        cand_base = base << wheel.bit_length()
        for r in residues:
            n = cand_base + r
            n |= (1 << (bits - 1))
            if all(n % p for p in _SMALL_PRIMES) and _miller_rabin(n):
                return n

def _safe_prime(bits: int):
    while True:
        q = _random_prime(bits - 1)
        p = 2*q + 1
        if _miller_rabin(p):
            return p, q

def _find_generator(p: int, q: int) -> int:
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

def elgamal_keygen(bits=64):
    p, q = _safe_prime(bits)
    g = _find_generator(p, q)
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt_chunk(pub, m: int):
    p, g, y = pub
    k = secrets.randbelow(p - 2) + 1
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return [a, b]  # lists serialize to JSON

def elgamal_decrypt_chunk(x: int, p: int, a: int, b: int) -> int:
    s = pow(a, x, p)
    return (b * pow(s, -1, p)) % p

# -----------------------------
# Text <-> chunks (CRITICAL FIX)
# -----------------------------
def max_chunk_bytes(p: int) -> int:
    # any chunk with <= this many bytes is guaranteed < p
    return max(1, (p.bit_length() - 1) // 8)

def text_to_chunks(txt: str, p: int):
    data = txt.encode("utf-8")
    chunk_size = max_chunk_bytes(p)
    chunks = [int.from_bytes(data[i:i+chunk_size], "big")
              for i in range(0, len(data), chunk_size)]
    return chunks, chunk_size, len(data)

def chunks_to_text(ints, msg_len: int, chunk_size: int) -> str:
    data = b"".join(i.to_bytes(chunk_size, "big") for i in ints)
    data = data[:msg_len]  # trim padding from the last block
    return data.decode("utf-8", errors="replace")

# -----------------------------
# Helper parsing/format
# -----------------------------
def pubkey_to_json(pub):
    p, g, y = pub
    return json.dumps({"p": int(p), "g": int(g), "y": int(y)})

def parse_pubkey(s: str):
    # Try JSON first
    try:
        obj = json.loads(s)
        return (int(obj["p"]), int(obj["g"]), int(obj["y"]))
    except Exception:
        pass
    # Fallback: safe tuple literal
    try:
        t = ast.literal_eval(s.strip())
        p, g, y = t
        return (int(p), int(g), int(y))
    except Exception as e:
        raise ValueError("Invalid public key format. Use JSON {\"p\":...,\"g\":...,\"y\":...} or (p,g,y).") from e

# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="ElGamal Demo", page_icon="🔐", layout="centered")
st.title("🔐 ElGamal Cryptosystem Demo")

page = st.sidebar.radio("Go to", ["Key Generation", "Encoder", "Decoder"])

# 1) Key Generation
if page == "Key Generation":
    st.header("1) Public / Private Key Generation")
    bits = st.slider("Key size (bits)", 32, 256, 64, help="Bigger = slower. For demo, 64–128 is fine.")
    if st.button("Generate Keys"):
        pub, priv = elgamal_keygen(bits)
        st.success(f"Keys generated with {bits}-bit safe prime")
        st.code(pubkey_to_json(pub), language="json")
        st.text_input("Private key x", str(priv))

# 2) Encoder
elif page == "Encoder":
    st.header("2) Encrypt a Message")
    pub_str = st.text_area("Public Key (JSON or tuple)", height=80, placeholder='{"p": 123, "g": 5, "y": 42}')
    msg = st.text_area("Enter your text message")
    if st.button("Encrypt"):
        try:
            pub = parse_pubkey(pub_str)
            p = pub[0]
            ints, chunk_size, msg_len = text_to_chunks(msg, p)
            cipher = [elgamal_encrypt_chunk(pub, m) for m in ints]
            package = {
                "p": int(p),
                "chunk_size": int(chunk_size),
                "msg_len": int(msg_len),
                "cipher": cipher
            }
            out = json.dumps(package)
            st.success(f"Encrypted in {len(cipher)} chunk(s).")
            st.code(out, language="json")
        except Exception as e:
            st.error(f"Encryption error: {e}")

# 3) Decoder
else:
    st.header("3) Decrypt a Message")
    priv_key = st.text_input("Private Key x")
    cipher_json = st.text_area(
        "Encrypted package (JSON from the Encoder step)",
        placeholder='{"p":..., "chunk_size":..., "msg_len":..., "cipher":[[a,b], ...]}',
        height=160
    )
    if st.button("Decrypt"):
        try:
            x = int(priv_key)
            pkg = json.loads(cipher_json)
            p = int(pkg["p"])
            chunk_size = int(pkg["chunk_size"])
            msg_len = int(pkg["msg_len"])
            pairs = pkg["cipher"]
            ints = [elgamal_decrypt_chunk(x, p, int(a), int(b)) for a, b in pairs]
            text = chunks_to_text(ints, msg_len, chunk_size)
            st.success("Decrypted message:")
            st.text_area("Plaintext", text, height=150)
        except Exception as e:
            st.error(f"Decryption error: {e}")
