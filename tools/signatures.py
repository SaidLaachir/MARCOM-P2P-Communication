# signatures.py
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import DSA 
from Cryptodome.Random import get_random_bytes

def generate_dss_keys(key_size=2048):
    """Génère une paire de clés DSA (utilisée pour la signature DSS)."""
    key = DSA.generate(key_size, get_random_bytes)
    return key, key.publickey()

def sign_msg(private_key, msg):
    """Signe un message avec la clé privée DSS/DSA."""
    h = SHA256.new(msg.encode())
    signer = DSS.new(private_key, 'fips-186-3') 
    return signer.sign(h)

def verify_msg(public_key, msg, signature):
    """Vérifie une signature avec la clé publique DSS/DSA."""
    h = SHA256.new(msg.encode())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False
        
if __name__ == "__main__":
    priv, pub = generate_dss_keys(1024)
    message = "Test de signature DSS."
    
    signature = sign_msg(priv, message)
    verified = verify_msg(pub, message, signature)
    
    print(f"--- Test Unitaire DSS Signature ---")
    print(f"Signature valide? {verified}")
    print("Succès." if verified else "Échec.")