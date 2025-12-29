# demo_p2p.py (Main Code)
from elgamal_key_gen import keygen_fast, encrypt_elgamal, decrypt_elgamal
from aes_gcm import encrypt_aes, decrypt_aes
from signatures import generate_dss_keys, sign_msg, verify_msg
from Cryptodome.Random import get_random_bytes
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Util.number import bytes_to_long, long_to_bytes # <-- Importation clé
import base64

def hybrid_demo():
    # --- Configuration ---
    ELGAMAL_KEY_BITS = 2048 
    DSS_KEY_BITS = 2048    
    message_text = "Salut Bob! Ceci est un message secret et authentifié."

    # --- 1. Génération des Clés ---
    bob_keys = keygen_fast(ELGAMAL_KEY_BITS)
    bob_pub = bob_keys["pub"]
    bob_priv = bob_keys["pvt"]
    
    alice_dss_priv, alice_dss_pub = generate_dss_keys(DSS_KEY_BITS)

    # --- 2. Préparation du Message (Alice) ---
    
    # Génération de la Clé de Session AES (32 octets = 256 bits)
    shared_aes_key = get_random_bytes(32) 
    
    # Chiffrement du message avec AES
    nonce, ciphertext_aes, tag = encrypt_aes(message_text, shared_aes_key)

    # Signature du message original (pour l'authenticité)
    signature = sign_msg(alice_dss_priv, message_text)
    
    # --- 3. Échange de Clé (Alice chiffre la clé AES pour Bob) ---
    
    # CORRECTION CRITIQUE: Conversion de bytes en Python long, puis en Integer de PyCryptodome.
    key_long = bytes_to_long(shared_aes_key)
    key_int = Integer(key_long) 
    
    # Chiffrement de la clé AES (Integer) avec la clé publique ElGamal de Bob
    ciphertext_elgamal = encrypt_elgamal(key_int, bob_pub)
    
    # --- 4. Côté Réception (Bob) ---
    
    # Bob déchiffre la clé AES avec sa clé privée ElGamal
    decrypted_key_int = decrypt_elgamal(ciphertext_elgamal, bob_priv)
    
    # Reconversion de la clé AES (Integer) en bytes (32 octets)
    decrypted_aes_key = long_to_bytes(decrypted_key_int, 32)
    
    # Bob vérifie l'authenticité (Signature)
    verified = verify_msg(alice_dss_pub, message_text, signature)
    
    # Bob déchiffre le message avec la clé AES récupérée
    try:
        decrypted_msg = decrypt_aes(nonce, ciphertext_aes, tag, decrypted_aes_key)
    except ValueError:
        decrypted_msg = "ERREUR DE DÉCHIFFREMENT/AUTHENTIFICATION AES (Clé incorrecte ou Tag altéré)"

    # --- 5. Affichage des Résultats ---
    
    print("--- Démonstration Cryptographique Hybride ---")
    print(f"Clé AES (Original) : {base64.b64encode(shared_aes_key).decode()}")
    print(f"Clé AES (Déchiffrée) : {base64.b64encode(decrypted_aes_key).decode()}")
    print("-" * 50)
    print(f"Message Chiffré (AES) : {base64.b64encode(ciphertext_aes).decode()}")
    print(f"Clé de session chiffrée (ElGamal) : C1={ciphertext_elgamal[0]} C2={ciphertext_elgamal[1]}")
    print("-" * 50)
    print(f"Message Déchiffré : {decrypted_msg}")
    print(f"Signature d'Alice valide ? {'OUI' if verified else 'NON'}")

if __name__ == "__main__":
    hybrid_demo()