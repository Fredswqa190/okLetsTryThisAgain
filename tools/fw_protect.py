#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Cipher import ChaCha20_Poly1305
import util

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        print('firmware:' +str(len(firmware)))
        fwSize=len(firmware)
        
    # Reads keys, IV, nonce, etc for AES and CHA 
    with open('/home/jovyan/work/okLetsTryThisAgain/tools/secret_build_output.txt', 'rb') as f:
        aesKey = f.read(16)
        aesiv = f.read(16)
        f.close()

    #gets firmware and firmware size
    firmwareAndSize = fwSize.to_bytes(2, "big")+ firmware
    print(len(firmwareAndSize))
    hash = SHA256.new()
    hash.update(firmware)
    hash_value = hash.digest()
    print(hash_value)
    firmwareAndSize+=hash.digest()
    #fwsize(2)+firmware(variable)+hash(32)

    # Encrypt FIRWMARE with AES-CBC
    cipherNew = AES.new(aesKey, AES.MODE_CBC, iv=aesiv)

    chunks=[]
    for i in range(int(len(firmwareAndSize)/16) - 1):
        AESoutput = firmwareAndSize[i*16:((i+1)*16)]
        chunks.append(AESoutput)

    encrypted = []
    for chunk in chunks:
        AESoutput = cipherNew.encrypt(pad(chunk, AES.block_size))
        encrypted.append(AESoutput)
    
    # Adds AES to firmware blob 
    # Hash firmware blob (AES) using SHA 256

    cTextSize=len(AESoutput)

     # Writes hash into secret output file 
    with open('/home/jovyan/work/okLetsTryThisAgain/tools/secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 

    print('ciphertext: '+str(cTextSize))
    print('hash digest: ' + str(len(hash.digest())))
    print('message: ' + str(len(message.encode())))


    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HHH', version, len(firmwareAndSize), cTextSize)
    print(metadata)

    #adding size
    #structure: metadata, ctextsize, encrypted(size+actualFirmware+hash), message, 0
    #firmware_blob=metadata + encrypted + message.encode() + b'\x00'
    print('metadata: ' + str(len(metadata)))
    
    #print(len(firmware_blob))

    # Write firmware blob to outfile
    with open(outfile, 'wb') as outfile:
        outfile.write(metadata)
        for i in range (len(encrypted)):
            outfile.write(encrypted[i])
        outfile.write(message.encode())
        outfile.write(b'\x00')

    with open('/home/jovyan/work/okLetsTryThisAgain/tools/hi.txt', 'wb') as thing:
        #list = util.print_hex(firmware_blob)
        for i in range (len(encrypted)):
            thing.write(encrypted[i])
    
    with open('/home/jovyan/work/okLetsTryThisAgain/tools/hi.txt', 'rb') as thing3:
        everything = thing3.read()

    #AESoutput
        cipher = AES.new(aesKey, AES.MODE_CBC, iv=aesiv)
        data = cipher.decrypt(everything)
        with open('/home/jovyan/work/okLetsTryThisAgain/tools/pain.txt', 'wb') as thing2:
            thing2.write(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    #Encrypts firmware using AEs, then hashes using SHA *maybe*
    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)