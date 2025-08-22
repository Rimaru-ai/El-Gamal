import json, base64, secrets, time, io
from math import gcd
from hashlib import sha256

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# =========================
#   Primes & ElGamal (KEM)
# =========================

_SMALL_PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def _miller_rabin(n: int, k=7) -> bool:
    if n < 2: return False
    for p in _SMALL_PRIMES:
        if n == p: return True
        if n % p == 0: return False
    # write n-1 = 2^r * d
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

def keygen(bits=256):
    """Return (public, private) where public=(p,g,y), private=x."""
    p, q = _safe_prime(bits)
    g = _find_generator(p, q)
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    return (int(p), int(g), int(y)), int(x)

def kdf_from_shared_secret(s: int) -> bytes:
    # derive a 256-bit key from integer s
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, "big")
    return sha256(s_bytes).digest()  # 32 bytes

def kem_encapsulate(pub):
    """ElGamal KEM: returns (a, key) where a=g^k mod p and key = KDF(y^k mod p)."""
    p, g, y = pub
    k = secrets.randbelow(p - 2) + 1
    a = pow(g, k, p)        # "ephemeral public key"
    s = pow(y, k, p)        # shared secret
    key = kdf_from_shared_secret(s)
    return int(a), key

def kem_decapsulate(priv, p, a):
    s = pow(a, priv, p)     # shared secret using receiver's private key x
    return kdf_from_shared_secret(s)

# =========================
#    AES-GCM helpers
# =========================

def aes_gcm_encrypt(key: bytes, data: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

# =========================
#   Streamlit UI helpers
# =========================

def pub_to_json(pub):
    p, g, y = pub
    return json.dumps({"p": int(p), "g": int(g), "y": int(y)})

def pub_from_json(s: str):
    o = json.loads(s)
    return (int(o["p"]), int(o["g"]), int(o["y"]))

def make_package(p: int, g: int, a: int, nonce: bytes, ct: bytes, tag: bytes, meta=None):
    pkg = {
        "alg": "ElGamal-KEM + AES-GCM",
        "kdf": "SHA-256",
        "p": int(p),
        "g": int(g),
        "a": int(a),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "ct": b64e(ct),
        "meta": meta or {}
    }
    return json.dumps(pkg)

def parse_package(s: str):
    o = json.loads(s)
    return (
        int(o["p"]), int(o["g"]), int(o["a"]),
        b64d(o["nonce"]), b64d(o["ct"]), b64d(o["tag"]), o.get("meta", {})
    )

# =========================
#         UI
# =========================

st.set_page_config(page_title="Practical ElGamal Messenger", page_icon="🔐", layout="centered")
st.title("🔐 Practical Secure Messenger (ElGamal-KEM + AES-GCM)")

if "pub" not in st.session_state:
    st.session_state.pub = None
if "priv" not in st.session_state:
    st.session_state.priv = None

tabs = st.tabs(["1) Key Generation", "2) Encrypt", "3) Decrypt"])

# ---- Key Generation ----
with tabs[0]:
    st.subheader("Generate a key pair")
    sec = st.radio("Security level (prime size)", ["Demo (128-bit)", "Medium (256-bit)", "Strong (2048-bit)"], index=1,
                   help="Demo is very fast but insecure; 2048 is slow but closer to real-world.")
    bits = {"Demo (128-bit)": 128, "Medium (256-bit)": 256, "Strong (2048-bit)": 2048}[sec]

    if st.button("Generate keys"):
        with st.spinner(f"Generating safe prime (~{bits} bits). This can take a while..."):
            t0 = time.time()
            pub, priv = keygen(bits)
            t1 = time.time()
        st.session_state.pub, st.session_state.priv = pub, priv
        st.success(f"Done in {t1 - t0:.2f}s")
        st.caption("Public key:")
        st.json(json.loads(pub_to_json(pub)))
        st.caption("Private key x (keep secret):")
        st.code(str(priv))

    if st.session_state.pub:
        st.download_button("Download public key (JSON)", pub_to_json(st.session_state.pub), file_name="public_key.json")
        st.download_button("Download private key (text)", str(st.session_state.priv), file_name="private_key.txt")

# ---- Encrypt ----
with tabs[1]:
    st.subheader("Encrypt (Text or File)")
    col1, col2 = st.columns(2)
    with col1:
        if st.session_state.pub:
            use_session_pub = st.checkbox("Use my generated public key", value=True)
        else:
            use_session_pub = False
    with col2:
        pub_json = st.text_area("Public key (JSON)", value=pub_to_json(st.session_state.pub) if (use_session_pub and st.session_state.pub) else "")

    mode = st.radio("What to encrypt?", ["Text", "File"], horizontal=True)

    data_bytes = b""
    if mode == "Text":
        msg = st.text_area("Message")
        if msg:
            data_bytes = msg.encode("utf-8")
    else:
        up = st.file_uploader("Choose a file")
        if up:
            data_bytes = up.read()

    if st.button("Encrypt"):
        try:
            pub = pub_from_json(pub_json)
            p, g, _ = pub
            a, key = kem_encapsulate(pub)
            nonce, ct, tag = aes_gcm_encrypt(key, data_bytes)
            meta = {"mode": mode, "filename": up.name if mode == "File" and up else None, "ts": time.time()}
            package = make_package(p, g, a, nonce, ct, tag, meta=meta)
            st.success("Encrypted ✅")
            st.code(package, language="json")
            st.download_button("Download ciphertext (JSON)", package, file_name="ciphertext.json")
        except Exception as e:
            st.error(f"Encryption error: {e}")

# ---- Decrypt ----
with tabs[2]:
    st.subheader("Decrypt")
    col1, col2 = st.columns(2)
    with col1:
        priv_in = st.text_input("Private key x", value=str(st.session_state.priv) if st.session_state.priv else "")
    with col2:
        pub_json_in = st.text_area("Your public key (JSON)", value=pub_to_json(st.session_state.pub) if st.session_state.pub else "")

    uploaded_pkg = st.file_uploader("Upload ciphertext JSON", type=["json"])
    pkg_text = st.text_area("...or paste ciphertext JSON", height=160)

    if st.button("Decrypt"):
        try:
            priv = int(priv_in)
            # prefer uploaded file if present
            if uploaded_pkg is not None:
                pkg = uploaded_pkg.read().decode()
            else:
                pkg = pkg_text

            p_pkg, g_pkg, a, nonce, ct, tag, meta = parse_package(pkg)
            # We could cross-check p/g match user's pub, but not required for decapsulation
            key = kem_decapsulate(priv, p_pkg, a)
            pt = aes_gcm_decrypt(key, nonce, ct, tag)

            if meta.get("mode") == "File" and meta.get("filename"):
                st.success("Decrypted file ready ✅")
                st.download_button("Download decrypted file", pt, file_name=f"dec_{meta['filename']}")
            else:
                st.success("Decrypted text ✅")
                st.text_area("Plaintext", pt.decode("utf-8", errors="replace"), height=160)
        except Exception as e:
            st.error(f"Decryption error: {e}")

st.markdown("---")
st.caption("⚠️ Educational demo. For production, prefer vetted libraries and 2048+ bit keys.")
