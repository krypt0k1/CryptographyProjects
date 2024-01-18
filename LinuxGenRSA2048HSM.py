# Description: This script is used to generate a new keypair on a nShield HSM Edge device.

# Activate venv run : source /home/administrator/Documents/.venv/bin/activate
# install pkcs11 module : pip install python-pkcs11

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

lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
# The following environment variables are optional:

os.environ['CKNFAST_OVERRIDE_SECURITY_ASSURANCE'] = 'unwrap_mech;tokenkeys'
#os.environ['CKNFAST_DEBUG'] = '10'
#os.environ['CKNFAST_DEBUGFILE'] = '/opt/nfast/pkcs11_debug.log'


# Token label
token = lib.get_token(token_label='loadshared accelerator')

# Key label
PKCS11_KEY_LABEL = 'testkey'

# The following templates are used to generate a keypair on the HSM.

public_key_template = {pkcs11.Attribute.TOKEN: True,
                       pkcs11.Attribute.PUBLIC_EXPONENT: 65537,
                       pkcs11.Attribute.MODULUS_BITS: 2048,
                       pkcs11.Attribute.WRAP: True,
                       pkcs11.Attribute.VERIFY: True,
                      # pkcs11.Attribute.EXTRACTABLE: True,

                      }

private_key_template = {pkcs11.Attribute.TOKEN: True,
                        pkcs11.Attribute.PRIVATE: True,
                        pkcs11.Attribute.SENSITIVE: True,
                        pkcs11.Attribute.UNWRAP: True,                        
                        pkcs11.Attribute.MODIFIABLE: True,
                        pkcs11.Attribute.EXTRACTABLE: False,
                                            
}
    
                    
# Open Session with HSM and Generate Key Pair

with token.open(rw=True) as session:
    
    try:
        key = session.get_key(label=PKCS11_KEY_LABEL)
        sys.exit('object with label="%s" already exists' % PKCS11_KEY_LABEL)
    except pkcs11.exceptions.NoSuchKey:
        pass
    except pkcs11.MultipleObjectsReturned:
        sys.exit('multiple objects with label="%s" already exist' % PKCS11_KEY_LABEL)

    public, private = session.generate_keypair(pkcs11.KeyType.RSA, 2048, label=PKCS11_KEY_LABEL,
                                               public_template=public_key_template,
                                               private_template=private_key_template)

    print('public key: %s' % public)
    print('private key: %s' % private)
    

    



    # Export the public key

    #pub_key_der = pub_key[0].export()
    #print('public key DER: %s' % pub_key_der)
    
# Notes:
#     pkcs11.Attribute.EXTRACTABLE: True yields a CKR_TEMPLATE_INCONSISTENT when applied to public_template.
#     pkcs11.Attribute.EXTRACTABLE: False yields a CKR_TEMPLATE_INCONSISTENT when applied to private_template.