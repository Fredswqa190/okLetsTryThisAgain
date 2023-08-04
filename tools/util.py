#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import os
import socket
from tinyec import registry
import hashlib, secrets, binascii
from Crypto.PublicKey import ECC
from chacha20poly1305 import ChaCha20Poly1305

UART0_PATH = "/embsec/UART0"
UART1_PATH = "/embsec/UART1"
UART2_PATH = "/embsec/UART2"

class DomainSocketSerial:
    def __init__(self, ser_socket: socket.socket):
        self.ser_socket = ser_socket
    
    def read(self, length: int) -> bytes:
        if length < 1:
            raise ValueError("Read length must be at least 1 byte")
        
        return self.ser_socket.recv(length)
    
    def readline(self) -> bytes:
        line = b""

        c = self.ser_socket.recv(1)
        while c != b"\n":
            line += c
            c = self.ser_socket.recv(1)
        
        line += b'\n'
        return line

    def write(self, data: bytes):
        self.ser_socket.send(data)

    def close(self):
        self.ser_socket.close()
        del self

def print_hex(data):
    hex_string = ', 0x'.join(format(byte, '02x') for byte in data)
    print(hex_string)
    return hex_string

def eccKeygen(): # Not sure if we should touch this rn
    key = ECC.generate(curve='P-256')
    f = open('secret_build_output.txt','a')
    f.write(key.export_key(format='PEM'))
    f.write("\n")
    f.write(key.public_key().export_key(format='PEM'))

def chacha20poly1305Gen():
    key = os.urandom(32)
    cip = ChaCha20Poly1305(key)
    with open('firmware/gcc/main.bin', 'rb') as fp:
        firmware = fp.read()
    nonce = os.urandom(12)
    ciphertext = cip.encrypt(nonce, firmware)
    return ciphertext
    # Unfinished- write ciphertext
    # painrn

"""
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

msg = b'Text to be encrypted by ECC public key and ' \
      b'decrypted by its corresponding ECC private key'
print("original msg:", msg)
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", encryptedMsgObj)

decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)
"""