import argparse
import logging
import os
import pkcs11
from pprint import pprint
import sys

logging.basicConfig(level=logging.INFO)  # Config needed to default output to standard output
logger = logging.getLogger(__name__)

LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'),
                                  'toolkits', 'pkcs11', 'libcknfast.so')

GENERATE = 'generate'
DELETE = 'delete'
os.environ["CKNFAST_LOADSHARING"] = '1'
os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = 'unwrap_mech;tokenkeys'
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = '1'

if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s -%(name)s - %(levelame)s -%(message)s')  # Config needed to default output to standard output
    logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Entrust Python PKCS#11 key generator.',
                                     prog='aeskeygen.py',
                                    # prog='aeskeygen.py'' --delete --token-label "loadshared accelerator" --label "default_key_label"''                              
                                     usage='%(prog)s [options]' and '%(prog)s -[option]--token-label "loadshared accelerator" --label "default_key_label"\n',
                                        epilog="Example: %(prog)s --generate --label 'my_key' --key-size 256 --token-label 'loadshared accelerator'\n",
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
                        required=False,
                        default='loadshared accelerator')
    args = vars(parser.parse_args())
    return args


def main():
    args = parse_args()  # Parse the arguments
    generate = GENERATE in args and args[GENERATE]
    delete = DELETE in args and args[DELETE]


    key_label = args.get('label')  # Fetch the label from arguments
    key_size = args.get('key_size')  # Fetch the key size from arguments


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

    lib = pkcs11.lib(LIB)

    token = lib.get_token(token_label=args['token_label'])
    
    if token:
        logger.info("Token found: %s", token)
    else:
        logger.error("No token found with label='%s'.", args['token_label'])
        return


    with token.open(rw=True) as session:
        if generate:
            try:
                key = session.generate_key(pkcs11.KeyType.AES, key_size, label=key_label,
                                           template=template)

                # Add completion clause
                key_info = [
                    'Key Successfully Generated',
                    'Key Size: ' + str(key_size) + ' bits',
                    'Key Label: ' + key_label,
                    'Key Type: AES']
                
                pprint(key_info[::-1])
                  #  'Key Version:' (args['key_version']),
                   # 'Token Label:' (args['token_label']),
                
               # pprint(key_info)
                #logger.info(f'Key successfully generated: \n'
                #           f'Label: {key_label}\n'
                ##          f'Key Object: {key}\n')
            except Exception as e:
                logger.error("Error generating the key: %s", str(e))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(repr(e))
        raise e

