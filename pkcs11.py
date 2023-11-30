# Initialization & Token/ Slot Enumeration.


import pkcs11
from pkcs11 import *
 
# Specify the correct environment variable that contains the path to the PKCS#11 library
pkcs11_lib_path = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
 
# Load the PKCS#11 library from the specified path
lib = pkcs11.lib(pkcs11_lib_path)
 
# Get the token label from user input
token_label = input("Please enter the token label: ")
 
# Get a token object from the loaded library, specifying the user-provided token label
token = lib.get_token(token_label=token_label)
 
# Open a session
print('Opening session...\n',
      'Enter the following values:\n', )
 
rw_value = input('Read Write Session? (True or False): '),
pin = input("Enter your PIN: ")
user_pin = int(pin)
 
with token.open(rw=rw_value, user_pin=pin) as session:
    # Searches the provided token label
 
    for slot in lib.get_slots(token_present=True):
        token = slot.get_token()
        # mechanism = slot.get_mechanisms()
        print('Tokens Present:\n', token)
 
        # See the mechanisms for the slot
 
        # boolean_Mech = (input("See available mechanisms? Yes or No"))
 
        # See the objects of a slot
        for obj in session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.CLASS: ObjectClass.PUBLIC_KEY
 
        }):
            print('Objects Present:\n', obj)
 
        if token.label == '...':
            break
    #  Searches for the objects of that token
 
    print(session)
 
 
def close():
    close_session = session.close()
 
    close()
