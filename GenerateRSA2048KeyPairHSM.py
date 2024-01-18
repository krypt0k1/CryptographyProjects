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

os.environ['CKNFAST_LOADSHARING'] = '1'
PKCS_MODULE_PATH = os.environ['PKCS11_MODULE_PATH'] = 'C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll'
# The following environment variables are optional:

os.environ['CKNFAST_OVERRIDE_SECURITY_ASSURANCE'] = 'unwrap_mech;tokenkeys'
os.environ['CKNFAST_DEBUG'] = '10'
os.environ['CKNFAST_DEBUGFILE'] = 'C:\Users\\Administrator\\Desktop\PKCS11KCS11debug.txt'

# Key Label 
PKCS11_TOKEN_LABEL = 'testkey'


# The following template is used to generate a keypair on the HSM.

public_template = { pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
             pkcs11.Attribute.TOKEN: True,
             pkcs11.Attribute.LABEL: PKCS11_TOKEN_LABEL,
             pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
             pkcs11.Attribute.MODULUS_BITS: 2048,
             pkcs11.Attribute.SIGN: True,
             pkcs11.Attribute.VERIFY: True,
             pkcs11.Attribute.ENCRYPT: True,
             pkcs11.Attribute.DECRYPT: False,
             pkcs11.Attribute.WRAP: True,
             pkcs11.Attribute.UNWRAP: False,
             pkcs11.Attribute.SENSITIVE: False,
             pkcs11.Attribute.EXTRACTABLE: True,
             pkcs11.Attribute.ALWAYS_AUTHENTICATE: False,
             pkcs11.Attribute.PRIVATE: True,
             pkcs11.Attribute.Modulus: True,
             pkcs11.Attribute.PublicExponent: True,
             pkcs11.Attribute.PrivateExponent: True,
             pkcs11.Attribute.Prime1: True,
             pkcs11.Attribute.Prime2: True,
             pkcs11.Attribute.Exponent1: True,
             pkcs11.Attribute.Exponent2: True,
             pkcs11.Attribute.Coefficient: True,
             pkcs11.Attribute.PUBLIC_EXPONENT: 65537}
            
private_template = {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.LABEL: PKCS11_TOKEN_LABEL,
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                    pkcs11.Attribute.MODULUS_BITS: 2048,
                    pkcs11.Attribute.SIGN: True,
                    pkcs11.Attribute.VERIFY: True,
                    pkcs11.Attribute.ENCRYPT: False,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.WRAP: False,
                    pkcs11.Attribute.UNWRAP: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                    pkcs11.Attribute.ALWAYS_AUTHENTICATE: False,
                    pkcs11.Attribute.PRIVATE: True,
                    pkcs11.Attribute.Modulus: True,
                    pkcs11.Attribute.PrivateExponent: True,
                   }

# Open Session with HSM and Generate Key Pair

with token.open(rw=True) as session:
    try:
        key = session.get_key(label=PKCS11_TOKEN_LABEL)
        sys.exit('object with label="%s" already exists' % PKCS11_TOKEN_LABEL)
    except pkcs11.exceptions.KeyDoesNotExist:
        pass
    except pkcs11.MultipleObjectsReturned:
        sys.exit('multiple objects with label="%s" already exist' % PKCS11_TOKEN_LABEL)
       
    key = session.generate_keypair(pkcs11.KeyType.RSA, 2048, public_template, private_template)
