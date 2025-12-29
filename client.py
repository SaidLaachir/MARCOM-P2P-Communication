# client.py
import socket
import json
import base64
import threading

from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import bytes_to_long
from Cryptodome.Math.Numbers import Integer
from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import SHA256

from tools.elgamal_key_gen import encrypt_elgamal
from tools.aes_gcm import encrypt_aes, decrypt_aes
from tools.signatures import generate_dss_keys, verify_msg, sign_msg

SERVER_IP = ""
PORT = 30000
BUFFER_SIZE = 16384

sock = None
shared_aes_key = None
cli_dss_priv = None
srv_dss_pub_key = None


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


def start_client(ip, log):
    global sock, shared_aes_key, cli_dss_priv, srv_dss_pub_key

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, PORT))
    log(C("orange", "[CLIENT] Connected to server"))

    log(C("yellow", "[CLIENT][1] Generating DSS signing keys"))
    cli_dss_priv, cli_dss_pub = generate_dss_keys(2048)

    server_data = json.loads(sock.recv(BUFFER_SIZE).decode())
    srv_elgamal_pub = server_data["elgamal_pub"]
    srv_dss_pub_key = DSA.import_key(server_data["dss_pub_pem"])

    log(C("blue", "[CLIENT][2] Received ElGamal public key"))
    log(C("blue", f"[ELGAMAL] Public key = {srv_elgamal_pub}"))

    sock.send(json.dumps({
        "dss_pub_pem": cli_dss_pub.export_key(format="PEM").decode()
    }).encode())

    shared_aes_key = get_random_bytes(32)
    log(C("green", f"[AES] Generated key = {shared_aes_key.hex()}"))

    key_int = Integer(bytes_to_long(shared_aes_key))
    c1, c2 = encrypt_elgamal(key_int, srv_elgamal_pub)

    log(C("blue", "[CLIENT][3] Encrypting AES key with ElGamal"))
    log(C("blue", f"[ELGAMAL] c1 = {c1}"))
    log(C("blue", f"[ELGAMAL] c2 = {c2}"))

    sock.send(json.dumps({"c1": c1, "c2": c2}).encode())
    log(C("green", "[CLIENT] Secure channel established\n"))

    threading.Thread(target=receive_messages, args=(log,), daemon=True).start()


def receive_messages(log):
    global sock
    while True:
        try:
            raw = sock.recv(BUFFER_SIZE)
            if not raw:
                break

            packet = json.loads(raw.decode())
            nonce = base64.b64decode(packet["nonce"])
            ciphertext = base64.b64decode(packet["ciphertext"])
            tag = base64.b64decode(packet["tag"])
            signature = base64.b64decode(packet["signature"])

            msg = decrypt_aes(nonce, ciphertext, tag, shared_aes_key)

            h = SHA256.new(msg.encode()).hexdigest()
            valid = verify_msg(srv_dss_pub_key, msg, signature)

            log(C("purple", f"[SHA-256] {h}"))
            log(C("green", f"[AES] nonce={nonce.hex()} tag={tag.hex()}"))
            log(C("yellow", f"[DSS] Signature VALID = {valid}"))
            log(f"[SERVER] {msg}\n")

        except Exception as e:
            log(C("red", f"[CLIENT ERROR] {e}"))
            break


def send_message(msg, log):
    signature = sign_msg(cli_dss_priv, msg)
    nonce, ciphertext, tag = encrypt_aes(msg, shared_aes_key)

    sock.send(json.dumps({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "signature": base64.b64encode(signature).decode()
    }).encode())

    log(C("purple", f"[SHA-256] {SHA256.new(msg.encode()).hexdigest()}"))
    log(C("green", f"[AES] nonce={nonce.hex()} tag={tag.hex()}"))
    log(C("yellow", "[DSS] Message signed"))
    log(f"[YOU] {msg}\n")
