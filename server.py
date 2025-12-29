# server.py
import socket
import json
import base64
import threading

from Cryptodome.Util.number import long_to_bytes
from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import SHA256

from tools.elgamal_key_gen import keygen_fast, decrypt_elgamal
from tools.aes_gcm import encrypt_aes, decrypt_aes
from tools.signatures import generate_dss_keys, verify_msg, sign_msg

HOST = "0.0.0.0"
PORT = 30000
BUFFER_SIZE = 16384

conn = None
shared_aes_key = None
srv_dss_priv = None
client_dss_pub_key = None


# ===== COLOR HELPERS =====
def C(color, msg):
    colors = {
        "blue": "\033[94m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "purple": "\033[95m",
        "orange": "\033[33m",
        "red": "\033[91m",
        "end": "\033[0m",
    }
    return f"{colors[color]}{msg}{colors['end']}"


def start_server(log):
    global conn, shared_aes_key, srv_dss_priv, client_dss_pub_key

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    log(C("orange", "[SERVER] Waiting for client..."))
    conn, addr = server.accept()
    log(C("orange", f"[SERVER] Connected to {addr}"))

    # ===== STEP 1: ElGamal =====
    log(C("blue", "[SERVER][1] Generating ElGamal key pair"))
    keys = keygen_fast(2048)
    srv_elgamal_priv = keys["pvt"]
    srv_elgamal_pub = keys["pub"]
    log(C("blue", f"[ELGAMAL] Public key = {srv_elgamal_pub}"))

    # ===== STEP 2: DSS =====
    log(C("yellow", "[SERVER][2] Generating DSS signing keys"))
    srv_dss_priv, srv_dss_pub = generate_dss_keys(2048)

    # ===== STEP 3: Send public keys =====
    log(C("orange", "[SERVER][3] Sending ElGamal + DSS public keys"))
    conn.send(json.dumps({
        "elgamal_pub": srv_elgamal_pub,
        "dss_pub_pem": srv_dss_pub.export_key(format="PEM").decode()
    }).encode())

    # ===== STEP 4: Receive client DSS =====
    log(C("orange", "[SERVER][4] Receiving client DSS public key"))
    client_data = json.loads(conn.recv(BUFFER_SIZE).decode())
    client_dss_pub_key = DSA.import_key(client_data["dss_pub_pem"])

    # ===== STEP 5: Receive AES =====
    log(C("blue", "[SERVER][5] Receiving encrypted AES key (ElGamal)"))
    encrypted_aes = json.loads(conn.recv(BUFFER_SIZE).decode())
    log(C("blue", f"[ELGAMAL] c1 = {encrypted_aes['c1']}"))
    log(C("blue", f"[ELGAMAL] c2 = {encrypted_aes['c2']}"))

    aes_int = decrypt_elgamal(
        (encrypted_aes["c1"], encrypted_aes["c2"]),
        srv_elgamal_priv
    )
    shared_aes_key = long_to_bytes(aes_int, 32)

    log(C("green", "[SERVER][6] AES shared key established"))
    log(C("green", f"[AES] Key = {shared_aes_key.hex()}"))

    log(C("green", "[SERVER] Secure channel established\n"))

    threading.Thread(target=receive_messages, args=(log,), daemon=True).start()


def receive_messages(log):
    global conn
    while True:
        try:
            raw = conn.recv(BUFFER_SIZE)
            if not raw:
                break

            packet = json.loads(raw.decode())
            nonce = base64.b64decode(packet["nonce"])
            ciphertext = base64.b64decode(packet["ciphertext"])
            tag = base64.b64decode(packet["tag"])
            signature = base64.b64decode(packet["signature"])

            msg = decrypt_aes(nonce, ciphertext, tag, shared_aes_key)

            h = SHA256.new(msg.encode()).hexdigest()
            valid = verify_msg(client_dss_pub_key, msg, signature)

            log(C("purple", f"[SHA-256] {h}"))
            log(C("green", f"[AES] nonce={nonce.hex()} tag={tag.hex()}"))
            log(C("yellow", f"[DSS] Signature VALID = {valid}"))
            log(f"[CLIENT] {msg}\n")

        except Exception as e:
            log(C("red", f"[SERVER ERROR] {e}"))
            break


def send_message(msg, log):
    signature = sign_msg(srv_dss_priv, msg)
    nonce, ciphertext, tag = encrypt_aes(msg, shared_aes_key)

    conn.send(json.dumps({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "signature": base64.b64encode(signature).decode()
    }).encode())

    log(C("purple", f"[SHA-256] {SHA256.new(msg.encode()).hexdigest()}"))
    log(C("green", f"[AES] nonce={nonce.hex()} tag={tag.hex()}"))
    log(C("yellow", "[DSS] Message signed"))
    log(f"[YOU] {msg}\n")
