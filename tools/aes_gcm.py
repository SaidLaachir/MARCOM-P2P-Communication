# aes_gcm.py
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def encrypt_aes(msg, key):
    """Chiffre un message avec AES-256 en mode GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return cipher.nonce, ciphertext, tag

def decrypt_aes(nonce, ciphertext, tag, key):
    """Déchiffre et vérifie l'authenticité d'un message AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

if __name__ == "__main__":
    key = get_random_bytes(32)
    msg = "Message secret pour test unitaire AES."
    nonce, ct, tag = encrypt_aes(msg, key)
    
    print(f"--- 🔒 Test Unitaire AES-GCM ---")
    print("Ciphertext:", ct)
    
    try:
        decrypted_msg = decrypt_aes(nonce, ct, tag, key)
        print("Decrypted:", decrypted_msg)
        print("Succès.")
    except ValueError:
        print("Échec de la vérification/déchiffrement.")