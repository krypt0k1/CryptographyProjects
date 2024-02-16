# Early understanding of encryption/decryption operations.
#import pkcs11
 
# Define the HSM lib path
#LIB = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
#lib = pkcs11.lib(LIB)
 
# Define the token to utilize
 
#token = lib.get_token(token_label='loadshared accelerator')
 
# Define the session
 
#with token.open(rw=True, user_pin='1234')
    # Generate random iv (128) recommended.
    iv = session.generate_random(128)
    key = session.get_get(label='new_key')
 
# Encrypt
 
    ciphertext = key.encrypt(b'Hello World', mechanism_param=iv)
     
# Decrypt
 #   plaintext = key.decrypt(ciphertext, mechanism_param=iv)
 #   print(plaintext)



#####################################################################################
# Description : This script is used to encrypt files using an Entrust HSM key.
 
import os
import sys
import pkcs11
import logging
import threading
 
 
 
LOCK = threading.Lock()
logging.basicConfig(level=logging.INFO)
LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'),
                                  'toolkits', 'pkcs11', 'libcknfast.so')
lib = pkcs11.lib(LIB)
 
 
 
# Define environment variables.
os.environ["CKNFAST_LOADSHARING"] = "1"
os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = "all"
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = "1"
 
#
# Constants
#
TOKEN_LABEL = 'loadshared accelerator'
TOKEN_PIN = '1234'
AES_KEY_LABEL = 'new_key' 
     
token = lib.get_token(token_label=TOKEN_LABEL)
         
with token.open(rw=True ,user_pin=TOKEN_PIN) as session:
        iv = session.generate_random(128)
        key = session.get_key(label=AES_KEY_LABEL)
        if key is None:
            print("No key found")
            sys.exit(1)
         
        # Encrypt the file contents and output it to a file.
        input_file = "/home/administrator/Desktop/encrypt_me.txt"
        output_file = "/home/administrator/Desktop/encrypted.txt"
 
        with open(input_file, "rb") as file:
            data = file.read()
 
        ciphertext = key.encrypt(data, mechanism_param=iv)
 
        with open(output_file, "wb") as file:
            file.write(ciphertext)
 
        # Output the ciphertext to a file
        output_file = "/home/administrator/Desktop/encrypted.txt"
        with open(output_file, "wb") as file:
            file.write(ciphertext)   


