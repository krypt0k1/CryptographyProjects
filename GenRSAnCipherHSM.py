# Defining app banner. 

def create_banner(text, width=80, border_char='*'):
    lines = text.strip().split('\n')
    border = border_char * width

    print(border)
    for line in lines:
        print(f"{border_char} {line.ljust(width - 4)} {border_char}")
    print(border)

banner_text = """
Proprietary and Confidential
Entrust Data Corp & nCipher Security
Written by Armando Montero

**************************************************************************
DISCLAIMER:
This code is provided for example purposes only.
It is not intended for production use. It has not been tested for security.
nCipher disclaims all warranties, express or implied, including without
limitation, any implied warranties of fitness of this code for any
particular purpose. nCipher shall not be liable for any damages, however
caused, arising out of any use of this code.

Usage:
  * Enter the key label (e.g., mykey)
    * Enter the token label (e.g., loadshared accelerator)
        * Enter the token pin   
            * Enter the key size (e.g., 2048)
            * Do you want the public key to be a wrapping key? (y/n)
            * public key is generated
            * private key is generated
**************************************************************************

"""

create_banner(banner_text)

import pkcs11
import os
import sys

# Check if pkcs11 is installed
try:
    import pkcs11
except ImportError:
    print("pkcs11 module is not installed")

# Check the directories in sys.path
import sys

print(sys.path)

# If you're using a virtual environment, make sure pkcs11 is installed there
# You can use pip list to see the installed packages

# If there's a problem with your Python installation, you might need to reinstall Python

# This script is used to generate a new keypair on a nShield HSM Edge device.

# The following environment variables must be set:
#   - PKCS11_MODULE_PATH: the path to the pkcs11 module
#   - PKCS11_TOKEN_LABEL: the label of the token to use
#   - PKCS11_PIN: the pin of the token to use

os.environ['PKCS11_MODULE_PATH'] = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
os.environ['CKNFAST_LOADSHARING'] = '1'
os.environ['CKNFAST_FAKE_ACCELERATOR_LOGIN'] = '1'

# Defining the pkcs11 module library
lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])


# The following environment variables are optional:

#os.environ['CKNFAST_OVERRIDE_SECURITY_ASSURANCE'] = 'unwrap_mech;tokenkeys'
#os.environ['CKNFAST_DEBUG'] = '10'
#os.environ['CKNFAST_DEBUGFILE'] = '/opt/nfast/pkcs11_debug.log'


# Prompt for the PKCS11_KEY_LABEL
PKCS11_KEY_LABEL = input("Enter the key label: ")

# Prompt for the token label
PKCS11_TOKEN_LABEL = input("Enter the token label: ")

# Prompt for the PKCS11_PIN
PKCS11_PIN = input("Enter the token pin: ")

# Get the token using the provided label
token = lib.get_token(token_label=PKCS11_TOKEN_LABEL)


# Prompt for the key size
key_size = int(input("Enter the key size (e.g., 2048): "))
MODULUS_BITS = key_size

# Prompt to ask if user wants pubkey to be wrapping key.
WRAPPING_KEY = input("Do you want the public key to be a wrapping key? (y/n): ")

# Token label
token = lib.get_token(token_label=PKCS11_TOKEN_LABEL)

# The following templates are used to generate a keypair on the HSM.

public_key_template = {pkcs11.Attribute.TOKEN: True,
                       pkcs11.Attribute.PUBLIC_EXPONENT: 65537,
                       pkcs11.Attribute.MODULUS_BITS: MODULUS_BITS,
                       pkcs11.Attribute.WRAP: WRAPPING_KEY,
                       pkcs11.Attribute.VERIFY: True,
                       pkcs11.Attribute.MODIFIABLE: True,
                       pkcs11.Attribute.ENCRYPT: True,
                   
                    
                      

                      }

private_key_template = {pkcs11.Attribute.TOKEN: True,
                        pkcs11.Attribute.PRIVATE: True,
                        pkcs11.Attribute.SENSITIVE: True,
                        pkcs11.Attribute.UNWRAP: True,                        
                        pkcs11.Attribute.MODIFIABLE: True,
                        pkcs11.Attribute.EXTRACTABLE: False,
                        pkcs11.Attribute.DECRYPT: True,
                        pkcs11.Attribute.WRAP_WITH_TRUSTED: True,
                        pkcs11.Attribute.SIGN: True,
                                            
}
    
                    
# Open Session with HSM and Generate Key Pair

def format_key_output(key, key_type):
    key_info = f"{key_type} Key:\n"
    key_info += f"  Label: {getattr(key, 'label', 'N/A')}\n"
    key_info += f"  Key Size: {getattr(key, 'key_size', MODULUS_BITS)}-bit\n"
    key_info += f"  Key Type: {key.__class__.__name__}\n"
    key_info += f"  Exponent: {getattr(key, 'public_exponent', '65537')}\n"
  
    return key_info

with token.open(rw=True,user_pin=PKCS11_PIN) as session:
    
    try:
        key = session.get_key(label=PKCS11_KEY_LABEL)
        sys.exit('object with label="%s" already exists' % PKCS11_KEY_LABEL)
    except pkcs11.exceptions.NoSuchKey:
        pass
    except pkcs11.MultipleObjectsReturned:
        sys.exit('multiple objects with label="%s" already exist' % PKCS11_KEY_LABEL)

    public, private = session.generate_keypair(pkcs11.KeyType.RSA, key_size, label=PKCS11_KEY_LABEL,
                                               public_template=public_key_template,
                                               private_template=private_key_template)

    key_info = format_key_output(public, "Public Key")
    print(key_info)

    key_info = format_key_output(private, "Private Key")
    print(key_info)

    print("Key pair generated successfully")
