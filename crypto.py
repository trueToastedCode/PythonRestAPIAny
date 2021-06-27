from Crypto.Cipher import AES
import secrets
import hashlib
import base64
import binascii
import json
from tinyec import registry
from cryptography.fernet import Fernet

def get_hashed(data: bytes) -> bytes:
    return hashlib.sha256(data)

def get_key_for_fernet(key: str) -> bytes:
    return base64.b64encode(key.ljust(32, '0').encode('utf-8'))

def encrypt_fernet(data: bytes, key: str) -> bytes:
    return Fernet(get_key_for_fernet(key)).encrypt(data)

def decrypt_fernet(data: bytes, key: str) -> bytes:
    return Fernet(get_key_for_fernet(key)).decrypt(data)

curve = registry.get_curve('brainpoolP256r1')

def generate_keys():
    priv_key = secrets.randbelow(curve.field.n)
    pub_key = priv_key * curve.g
    return {'privateKey': priv_key, 'publicKey': pub_key}

def encrypt_aes_gcm(msg, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
    return ciphertext, aes_cipher.nonce, auth_tag

def decrypt_aes_gcm(ciphertext, nonce, auth_tag, secret_key):
    aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_ecc(msg, pub_key):
    ciphertext_priv_key = secrets.randbelow(curve.field.n)
    shared_ecc_key = ciphertext_priv_key * pub_key
    secret_key = ecc_point_to_256_bit_key(shared_ecc_key)
    ciphertext, nonce, auth_tag = encrypt_aes_gcm(msg, secret_key)
    ciphertext_pub_key = ciphertext_priv_key * curve.g
    return ciphertext, nonce, auth_tag, ciphertext_pub_key

def decrypt_ecc(encrypted_msg, priv_key):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg
    shared_ecc_key = priv_key * ciphertextPubKey
    secret_key = ecc_point_to_256_bit_key(shared_ecc_key)
    plaintext = decrypt_aes_gcm(ciphertext, nonce, authTag, secret_key)
    return plaintext

def get_ecc_encrypted_message_dict(encrypted_msg) -> dict:
    return {
        'ciphertext': binascii.hexlify(encrypted_msg[0]),
        'nonce': binascii.hexlify(encrypted_msg[1]),
        'authTag': binascii.hexlify(encrypted_msg[2]),
        'ciphertextPubKey': json.dumps({'x': encrypted_msg[3].x, 'y': encrypted_msg[3].y})
    }

"""
https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption
Example:

privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

msg = b'Text to be encrypted by ECC public key and ' \
      b'decrypted by its corresponding ECC private key'

encryptedMsg = encrypt_ecc(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}

decryptedMsg = decrypt_ecc(encryptedMsg, privKey)
"""
