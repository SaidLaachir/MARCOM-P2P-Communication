# elgamal_key_gen.py
import random
from sympy import randprime
from Cryptodome.Math.Numbers import Integer 

# --- Configuration ---
KEY_BITS = 2048 
MESSAGE = 42

# --- 1. Génération de Clé Rapide ---
def keygen_fast(keysize:int=KEY_BITS):
    """
    Génère les clés ElGamal rapidement en utilisant un nombre premier simple de sympy.
    Retourne: {"pub": (p, g, beta), "pvt": (p, x)}
    """
    p = randprime(2**(keysize-1), 2**keysize)
    g = 5
    x = random.randrange(2, p - 1)
    beta = pow(g, x, p)
    return {"pub": (p, g, beta), "pvt": (p, x)}

# --- 2. Chiffrement (Encryption) ---
def encrypt_elgamal(m, pubKey):
    """
    Chiffre un message (doit être un objet Integer) 'm' avec la clé publique (p, g, beta).
    
    Correction: Utilisation explicite de m.__mul__(...) pour éviter l'OverflowError
    causé par la multiplication de deux très grands nombres (256 bits * 2048 bits).
    """
    p, g, beta = pubKey
    k = random.randrange(2, p - 1)
    
    # 1. Préparer les Integer pour l'opération de grand nombre
    p_integer = Integer(p) 
    beta_integer = Integer(beta) 
    
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # 2. Calcul de beta^k mod p en utilisant l'opération Integer.__pow__
    beta_pow_k = beta_integer.__pow__(k, p_integer) 
    
    # 3. Correction Finale de l'OverflowError: Utiliser la méthode __mul__ sur m
    m_beta_pow_k = m.__mul__(beta_pow_k) 
    
    # 4. Réduction modulo p
    c2 = m_beta_pow_k % p_integer
    
    # On renvoie c2 en tant qu'entier natif pour la sortie
    return (c1, int(c2))

# --- 3. Déchiffrement (Decryption) ---
def decrypt_elgamal(c, pvtKey):
    """
    Déchiffre le chiffré (c1, c2) avec la clé privée (p, x).
    """
    p, x = pvtKey
    c1, c2 = c
    
    # 1. Calcul de s = c1^x mod p
    s = pow(c1, x, p)
    
    # 2. Calcul de l'inverse multiplicatif: s^-1 mod p. 
    inv_s = Integer(s).inverse(Integer(p)) 
    
    # 3. Correction: c2 doit être converti en Integer avant la multiplication par inv_s.
    m = (Integer(c2) * inv_s) % p 
    
    return m

# --- Bloc de Test Principal ---
if __name__ == "__main__":
    
    keys = keygen_fast(KEY_BITS)
    pub, pvt = keys["pub"], keys["pvt"]
    
    message_int = Integer(MESSAGE) 
    
    print(f"--- Test Unitaire ElGamal Rapide ({KEY_BITS} bits) ---")
    print(f"Message Original (Integer) : {message_int}")

    cipher = encrypt_elgamal(message_int, pub)
    print("\n--- Chiffrement ---")
    print(f"Chiffré (c1, c2) : {cipher}")

    clear_text = decrypt_elgamal(cipher, pvt)
    print("\n--- Déchiffrement ---")
    print(f"Message Déchiffré (int) : {clear_text}")
    
    if clear_text == MESSAGE:
        print("\nSuccès : Le déchiffrement correspond au message original.")
    else:
        print("\nÉchec du déchiffrement.")