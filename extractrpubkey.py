# Description: This script extracts the public key from the HSM.
# Supported algorithms: RSA, EC, DSA
# Author: Armando Montero 
# Date: March 2024
# Version: 1.0

import pkcs11
import os
import sys
import argparse
import logging
import time
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key
from pkcs11.util.dsa import encode_dsa_public_key
from asn1crypto import pem


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
    parser = argparse.ArgumentParser(prog='extractpubkey.py',
                                     usage='%(prog)s [options]',
                                     description=' Extract RSA Public Key from nShield HSM.',
                                     epilog="Example: %(prog)s --extract --algorithm RSA --token-label 'loadshared accelerator' --label my_RSA_key --output /home/user/public_key",                                     
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     add_help=True)
    
    parser.add_argument('-e', '--export',
                        help='Export the public key from the HSM.',
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
    parser.add_argument('-alg','--algorithm',
                        help='Algorithm type for the key.',
                        required=False,
                        choices = ['RSA', 'EC', 'DSA'],
                        default='RSA')
                        
    
    args = parser.parse_args()
    
    return args



# Main function.
def main():
    args = parse_args()  # Parse the arguments
    
    if args.export:  # Direct attribute access
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label=args.token_label)
        if token:
            logger.info("Token found: %s", token)
            time.sleep(0.5) # Added sleep time to allow for better readability of the logs and printout messages.
            
            with token.open(rw=True) as session:
                try:
                    if args.algorithm == 'RSA':
                        public_key = session.get_key(label=args.label, object_class=pkcs11.ObjectClass.PUBLIC_KEY, key_type = pkcs11.KeyType.RSA)
                        logger.info(f"Public key found with label: {public_key.label}")
                        time.sleep(1)
                        extracted_public_key = pkcs11.util.rsa.encode_rsa_public_key(public_key)
                        logger.info("Public key extracted.")
                        time.sleep(1)
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    elif args.algorithm == 'EC':
                        public_key = session.get_key(label=args.label, object_class=pkcs11.ObjectClass.PUBLIC_KEY, key_type = pkcs11.KeyType.EC)
                        logger.info(f"Public key found with label: {public_key.label}")
                        time.sleep(1)
                        extracted_public_key = pkcs11.util.ec.encode_ec_public_key(public_key)
                        logger.info("Public key extracted.")
                        time.sleep(1)
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    elif args.algorithm == 'DSA':
                        public_key = session.get_key(label=args.label, object_class=pkcs11.ObjectClass.PUBLIC_KEY, key_type = pkcs11.KeyType.DSA)
                        logger.info(f"Public key found with label: {public_key.label}")
                        time.sleep(1)
                        extracted_public_key = pkcs11.util.dsa.encode_dsa_public_key(public_key)
                        logger.info("Public key extracted.")
                        time.sleep(1)
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    else:
                        sys.exit("Invalid key type. Please select a valid key type.")
                     
                    
                    
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
                    
                    # Write the public key to the specified output file in DER format
                    with open(der_output, 'wb') as der_file:
                        der_file.write(extracted_public_key)
                        logger.info(f'Writing public key to {args.output}.der in DER format')
                       
                                                     
                    # Write the public key to the specified output file in PEM format                      
                    with open(pem_output, 'wb') as pem_file:
                        # Convert the public key to PEM format and save it to a file. 
                        pem_bytes = pem.armor('PUBLIC KEY', extracted_public_key)
                        pem_file.write(pem_bytes)
                        logger.info(f'Writing public key to {args.output}.pem in PEM format')  
                        time.sleep(1)
                        logger.info("Public key extraction completed.")                     
                      

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
                except pkcs11.SessionClosed:
                    logger.error("Session closed early.")
                except pkcs11.ObjectHandleInvalid:
                    logger.error("Object handle invalid.")                       
                except Exception as e:
                    logger.error(f"An error occurred, review the logs: {e}")
        
        # Close the session after function is completed. 
               
      

if __name__ == "__main__":
    main()

