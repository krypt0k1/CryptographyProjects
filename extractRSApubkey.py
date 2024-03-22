# Description: This script extracts the public key from the HSM.

import pkcs11
import os
import argparse
import logging
from pkcs11.util.rsa import encode_rsa_public_key



# Defining the logger.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Path to the PKCS#11 library.
LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'), 'toolkits', 'pkcs11', 'libcknfast.so')

# Environment variables.
os.environ["CKNFAST_LOADSHARING"] = '1'
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = '1'

# Arguments parser.
def parse_args():
    parser = argparse.ArgumentParser(description='Entrust Python PKCS#11 Extract Public Key from HSM.',
                                     prog='rsaextractpub.py',
                                     usage='%(prog)s rsaextractpub.py [options]',
                                     epilog="Example: %(prog)s --extract --token-label 'loadshared accelerator' --label 'my_key'",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     add_help=True)
    parser.add_argument('-e', '--extract',
                        help='Extract the public key from the HSM.',
                        required=True,
                        default=False,
                        action="store_true")
    parser.add_argument('-l', '--label',
                        help='Label name for the key.',
                        required=True,
                        default='default_key_label')
    parser.add_argument('-t', '--token-label',
                        help='Token label to use.',
                        required=True,
                        default='loadshared accelerator')
    parser.add_argument('-o', '--output',
                        help='Output file name.',
                        required=True,
                        default='public_key.txt')
    args = parser.parse_args()
    
    return args



# Main function.
def main():
    args = parse_args()  # Parse the arguments
    if args.extract:  # Direct attribute access
        
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label=args.token_label)
        if token:
            logger.info("Token found: %s", token)
            with token.open(rw=True) as session:
                try:
                    public_key = session.get_key(label=args.label, object_class=pkcs11.ObjectClass.PUBLIC_KEY)
                    logger.info("Public key found: %s", public_key.label)
                    
                    extracted_public_key = pkcs11.util.rsa.encode_rsa_public_key(public_key)
                    logger.info("Extracting public key...")
                    logger.info("Public key extracted in DER format: %s", public_key.label + " size:" + str(public_key.key_length) + " bits" + " type:"+ str(public_key.key_type))
                    

                    # Write the public key attributes to the specified output file
                    with open(args.output, 'wb') as file:
                        file.write(extracted_public_key)
                        logger.info(f"Public key details saved to {args.output}")
                        
                        
                    
                except pkcs11.exceptions.NoSuchKey:
                    logger.error("No key found with label='%s'.", args.label)
                except pkcs11.exceptions.FunctionFailed:
                    logger.error("Failed to extract public key.")
                except Exception as e:
                    logger.error(f"An error occurred, review the logs: {e}")
       

if __name__ == "__main__":
    main()

