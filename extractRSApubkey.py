# Description: This script extracts the public key from the HSM.

import pkcs11
import os
import argparse
import logging
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_private_key, decode_rsa_public_key
from asn1crypto import pem, x509
from pkcs11 import Attribute





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
    parser = argparse.ArgumentParser(prog='rsatool.py',
                                     usage='%(prog)s [options]',
                                     description='python-pcks11 | Import & Extract RSA Public Key from nShield HSM.',
                                     epilog="Example: %(prog)s --extract --token-label 'loadshared accelerator' --label my_key",                                     
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     add_help=True)
    
    parser.add_argument('-e', '--extract',
                        help='Extract the public key from the HSM.',
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument('-l', '--label',
                        help='Label name for the key to import or extract.',
                        required=False,
                        default=False)
    parser.add_argument('-t', '--token-label',
                        help='Token label to use.',
                        required=False,
                        default='loadshared accelerator')
    parser.add_argument('-o', '--output',
                        help='Output file name.',
                        required=False,
                        default='public_key.txt')
    
    args = parser.parse_args()
    
    return args

# Main function.
def main():
    args = parse_args()  # Parse the arguments
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
                    
                    
                    # Write the public key attributes to the specified output file
                    if args.output.endswith('.pem'):
                        pem_output = args.output
                        der_output = args.output[:-4] + '.der'
                    elif args.output.endswith('.der'):
                        pem_output = args.output[:-4] + '.pem'
                        der_output = args.output
                    else:
                        pem_output = args.output + '.pem'
                        der_output = args.output + '.der'
                    
                    with open(der_output, 'wb') as der_file:
                        der_file.write(extracted_public_key)
                        logger.info("Public key extracted in DER format: %s", public_key.label + " size:" + str(public_key.key_length) + " bits" + " type:"+ str(public_key.key_type))
                        
                    # Write the public key to the specified output file in PEM format
                    cert = x509.Certificate.load(extracted_public_key)  
                    with open(pem_output, 'wb') as pem_file:
                        pem_bytes = pem.armor('CERTIFICATE', extracted_public_key)
                        pem_file.write(pem_bytes)
                        logger.info(f'Writing public key to {args.output} in PEM format')
                        der_bytes = cert.dump()
                        pem_bytes = pem.armor('CERTIFICATE', der_bytes)
                        pem_file.write(pem_bytes)
                        logger.info(f"Public key saved to {args.output} in PEM format")
                            

                # Error handling.     
                except pkcs11.exceptions.NoSuchKey:
                    logger.error("No key found with label='%s'.", args.label)
                except pkcs11.NoSuchToken:
                    logger.error("No token found with label='%s'.", args.token_label)
                except pkcs11.TokenNotPresent:
                    logger.error("Token not present.")
                except pkcs11.exceptions.FunctionFailed:
                    logger.error("Failed to extract public key.")
                except pkcs11.FunctionCancelled:
                    logger.error("Function cancelled.")               
                except pkcs11.ArgumentsBad:
                    logger.error("Bad arguments.")
                except pkcs11.SessionHandleInvalid:
                    logger.error("Session handle invalid.")
                except pkcs11.SessionClosed:
                    logger.error("Session closed.")
                except pkcs11.ObjectHandleInvalid:
                    logger.error("Object handle invalid.")
                       
                except Exception as e:
                    logger.error(f"An error occurred, review the logs: {e}")

if __name__ == "__main__":
    main()

