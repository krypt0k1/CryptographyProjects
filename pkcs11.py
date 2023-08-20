import os
import pkcs11
from pkcs11 import *
 
 
 
# Specify the correct environment variable that contains the path to the PKCS#11 library
pkcs11_lib_path = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
 
# Load the PKCS#11 library from the specified path
lib = pkcs11.lib(pkcs11_lib_path)
 
# Get a token object from the loaded library, specifying the token label ('loadshared accelerator' in this case)
token = lib.get_token(token_label='loadshared accelerator')
 
# FYI token_label will need one of the slot names from your /opt/nfast/cklist output.
# Given that the CKNFAST_LOADSHARING = 1 variable puts all slots tokens into a singular slot, we're able to see them all pop at once.
 
# Open a session with the token, indicating that it's a read-write session and providing the user PIN ('1234' in this case) for authentication
 
# To login as Security Officer (SO) change user_pin to so_pin
 
# example:
#with token.open(rw=True, so_pin= 'asg123;') as session:
 
# Login as user
with token.open(rw=True, user_pin='1234') as session:
     print(session)
 
# Gets the slots names
 
for slot in lib.get_slots():
    token = slot.get_token()
    print(token)
 
    if token.label == '...':
        break
