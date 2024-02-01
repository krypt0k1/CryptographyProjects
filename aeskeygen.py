import argparse
import logging
import os
import pkcs11
from pprint import pprint
import sys

# Setup Configuration
logging.basicConfig(level=logging.INFO)  # Config needed to default output to standard output
logger = logging.getLogger(__name__)

# Define the PKCS#11 DLL path
LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'),
                                  'toolkits', 'pkcs11', 'libcknfast.so')
# Define argument options.

GENERATE = 'generate'
DELETE = 'delete'
FIND_TOKEN = 'find-token'

# Define environment variables. 
os.environ["CKNFAST_LOADSHARING"] = '1'
os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = 'unwrap_mech;tokenkeys'
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = '1'

# Define arguments. 
def parse_args():
    """
    Parse command line arguments for the AES key generator.

    Returns:
        dict: A dictionary containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Entrust Python PKCS#11 AES Key Manager/Generator.\n\n'
                            'This script is used to generate, delete, and find AES keys in an Entrust HSM.',                                   
                          prog='aeskeygen.py',
                          usage='%(prog)s [--generate]' and '%(prog)s [--find-token] --token-label "loadshared accelerator" --label "default_key_label"\n',
                             epilog="Example: %(prog)s --generate --label 'my_key' --key-size 256 --token-label 'loadshared accelerator'\n"
                                 "       %(prog)s --find-token --token-label 'loadshared accelerator'\n"
                                 "       %(prog)s --delete --label 'my_key' --token-label 'loadshared accelerator'\n",
                          
                          formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                          add_help=True)
    parser.add_argument('-d', '--delete',
                   help='Delete the keys with the given version',
                   required=False,
                   default=False,
                   action="store_true")
    parser.add_argument('-v', '--key-version',
                        help='numerical version of keys to generate',
                        required=False,
                        default=2)
    parser.add_argument('-g', '--generate',
                        help='generate new keys',
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument('-l', '--label',
                        help='plaintext label name for the key',
                        required=False,
                        default='default_key_label')  # Default label if none is provided
    parser.add_argument('-s', '--key-size',
                        help='size of the key in bits',
                        required=False,
                        type=int,
                        choices=[128, 192, 256],  # Restrict key sizes to 128, 192, or 256
                        default=256)  # Default key size if none is provided
    parser.add_argument('-t', '--token-label',
                        help='token label to use',
                        required=True,
                        default='loadshared accelerator')
    parser.add_argument('-f', '--find-token',
                        help='find the token with the given label',
                        required=False,
                        action="store_true",
                        default=False,                       
                        )
    

    args = vars(parser.parse_args())
    return args

# Define the main function and options 
def main():
    args = parse_args()  # Parse the arguments
    generate = GENERATE in args and args[GENERATE]
    delete = DELETE in args and args[DELETE]
    token_found = FIND_TOKEN in args and args[FIND_TOKEN]
    
    # Grab arguments from input. 
    key_label = args.get('label')  # Fetch the label from arguments
    key_size = args.get('key_size')  # Fetch the key size from arguments
    user_pin = args.get('pin') # Fetch the pin from arguments. 
    token_label = args.get('token_label')  # Fetch the token label from arguments

    # Template key. 
    # Change accordingly
    # Plan to add functionality to grab boolean values within arguments to customize the CKA_ATTRIBUTES of the key. 
    template = {pkcs11.Attribute.TOKEN: True,
                pkcs11.Attribute.PRIVATE: False,
                pkcs11.Attribute.MODIFIABLE: True,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.WRAP_WITH_TRUSTED: True,
                pkcs11.Attribute.ENCRYPT: False,
                pkcs11.Attribute.DECRYPT: False,
                pkcs11.Attribute.WRAP: True,
                pkcs11.Attribute.UNWRAP: False,
                pkcs11.Attribute.SIGN: False,
                pkcs11.Attribute.VERIFY: False}

    # Initializes the library 
    lib = pkcs11.lib(LIB)
    # Grabs the token label from the syntax argument. 
    token = lib.get_token(token_label=token_label)
  
    # Functionality for token_found option          
    if args['find_token']:
        try:
            lib = pkcs11.lib(LIB)
            token = lib.get_token(token_label=args['token_label'])
            logger.info("Token found: %s", token)
        except pkcs11.exceptions.TokenNotPresent:
            logger.error("No token found with label='%s'.", args['token_label'])
            return
        except Exception as e:
            logger.error("An error occurred while finding the token: %s", str(e))
            return
    # Confirms that the token was found after calling it. 
    if token:
        logger.info("Token found: %s", token)

    # Open a session with the token
    with token.open(rw=True, user_pin=user_pin) as session:
      
        # Functionality for generate option       
        if generate:
            try:
                key = session.generate_key(pkcs11.KeyType.AES, key_size=key_size, label=key_label,
                                           template=template)

                # Add completion clause
                key_info = [
                    'Key Successfully Generated',
                    'Key Size: ' + str(key_size) + ' bits',
                    'Key Label: ' + key_label,
                    'Key Type: AES']

                # Print the completion clause and key information. 
                pprint(key_info[::-1])
            except Exception as e:
                logger.error('Failed to generate key: %s', str(e))

                key_info = [
                    'Key Successfully Generated',
                    'Key Size: ' + str(key_size) + ' bits',
                    'Key Label: ' + key_label,
                    'Key Type: AES']

              # Print the completion clause and key information. 
                pprint(key_info[::-1])
     
          # Error handling          
            except Exception as e:
                logger.error("Error generating the key: %s", str(e))
      # Functionality for delete option          
        if delete:
            try:
                key = session.get_key(label=key_label)
                logger.info("found object: %s", str(key))
                key.destroy()
            except pkcs11.NoSuchKey:
                logger.error('Didn\'t find the key.')
            except pkcs11.MultipleObjectsReturned:
                logger.error('multiple objects with label="%s"', key_label)

# Call to main function. 
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(repr(e))
        raise e

    except Exception as e:
        logger.error(repr(e))
        raise e
