import streamlit as st
import secrets
from math import gcd

# -----------------------------
# Utilities
# -----------------------------

_small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]

def _miller_rabin(n: int, k=5) -> bool:
    if n < 2:
        return False
    for p in _small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
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

def random_prime(bits=16):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(n):
            return n

def safe_prime(bits=16):
    while True:
        q = random_prime(bits - 1)
        p = 2 * q + 1
        if _miller_rabin(p):
            return p, q

def find_generator(p, q):
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
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(pub_key, m: int):
    p, g, y = pub_key
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
# Streamlit UI
# -----------------------------
st.title("🔐 ElGamal Cryptosystem Demo")

st.sidebar.header("Choose Functionality")
choice = st.sidebar.radio("Go to", ["Key Generation", "Encoder", "Decoder"])

# 1) Key Generation
if choice == "Key Generation":
    st.header("1️⃣ Public/Private Key Generation")
    bits = st.slider("Select key size (bits)", 16, 64, 32)
    if st.button("Generate Keys"):
        pub, priv = elgamal_keygen(bits)
        st.success(f"✅ Keys generated with {bits}-bit safe prime")
        st.text_area("Public Key (p, g, y)", str(pub), height=100)
        st.text_input("Private Key (x)", str(priv))

# 2) Encoder
elif choice == "Encoder":
    st.header("2️⃣ Encrypt a Message")
    pub_key_str = st.text_area("Enter Public Key (as tuple: p,g,y)")
    message = st.text_input("Enter your text message")
    if st.button("Encrypt"):
        try:
            pub = eval(pub_key_str)
            # Convert text to integer (basic encoding)
            m_int = int.from_bytes(message.encode(), "big") % pub[0]
            ct = elgamal_encrypt(pub, m_int)
            st.success("✅ Message Encrypted")
            st.text_area("Ciphertext (a, b)", str(ct))
        except Exception as e:
            st.error(f"Error: {e}")

# 3) Decoder
elif choice == "Decoder":
    st.header("3️⃣ Decrypt a Message")
    pub_key_str = st.text_area("Enter Public Key (as tuple: p,g,y)")
    priv_key_str = st.text_input("Enter Private Key (x)")
    ciphertext_str = st.text_area("Enter Ciphertext (as tuple: a,b)")
    if st.button("Decrypt"):
        try:
            pub = eval(pub_key_str)
            priv = int(priv_key_str)
            ct = eval(ciphertext_str)
            m_int = elgamal_decrypt(priv, pub, ct)
            # Convert integer back to text
            decrypted = m_int.to_bytes((m_int.bit_length() + 7)//8, "big").decode(errors="ignore")
            st.success("✅ Message Decrypted")
            st.text_area("Decrypted Message", decrypted)
        except Exception as e:
            st.error(f"Error: {e}")
