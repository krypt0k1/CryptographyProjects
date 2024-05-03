# This class will manage  export of public keys. 
# It uses the python-pkcs11 wrapper to interact with the nCipher PKCS11 library.
# Supports Public Key export for RSA, DSA, and EC algorithms.

import sys
import time
import pkcs11
import logging
import asn1crypto.pem as pem
from pkcs11 import KeyType, ObjectClass
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key
from pkcs11.util.dsa import encode_dsa_public_key
from Arguments import *

# Create an instance of the Arguments class to parse the arguments.
args = Arguments().parse()

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "Import/Export  ")


# Class to manage Import and Export of public keys.
class Export:
    def __init__(self, export_key):        
        self.export_key = export_key
    
         
    def export_pub_key(self, args):
                    # Load the PKCS#11 library
                    lib = pkcs11.lib(args.lib_path)
                    logger.info(f"PKCS#11 library loaded successfully.")
                    time.sleep(1)

                    # Load the token
                    token = lib.get_token(token_label=args.token_label)
                    logger.info(f"Token label: {args.token_label} loaded successfully.")

                    # Open a session
                    session = token.open(rw=True, user_pin=args.pin)
                    logger.info(f"Session opened successfully.")

                    if args.algorithm == 'RSA':
                        public_key = session.get_key(label=args.key_label, object_class=pkcs11.ObjectClass.PUBLIC_KEY, key_type = pkcs11.KeyType.RSA)
                        logger.info(f"Public key found with label: {public_key.label}")
                   
                        extracted_public_key = encode_rsa_public_key(public_key)
                        logger.info("Public key extracted.")
                       
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    elif args.algorithm == 'EC':
                        public_key = session.get_key(label=args.key_label, object_class= ObjectClass.PUBLIC_KEY, key_type = KeyType.EC)
                        logger.info(f"Public key found with label: {public_key.label}")
                    
                        extracted_public_key = encode_ec_public_key(public_key)
                        logger.info("Public key extracted.")
                    
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    elif args.algorithm == 'DSA':
                        public_key = session.get_key(label=args.key_label, object_class= ObjectClass.PUBLIC_KEY, key_type = KeyType.DSA)
                        logger.info(f"Public key found with label: {public_key.label}")
                    
                        extracted_public_key = encode_dsa_public_key(public_key)
                        logger.info("Public key extracted.")
                    
                        logger.info("Starting to write to file...")
                        time.sleep(1)
                    else:
                        sys.exit("Invalid key type. Please select a valid key type.")
                     
                    
                    
                    # Write the public key attributes to the specified output file
                 # Write the public key attributes to the specified output file
                    if args.output_path is not None:
                        if args.output_path.endswith('.pem'):
                            pem_output = args.output_path
                            der_output = args.output_path[:-4] + '.der'
                        elif args.output_path.endswith('.der'):
                            pem_output = args.output_path[:-4] + '.pem'
                    else:
                        logger.error("Output path is not provided.")
                        sys.exit(1)
                    
                    # Write the public key to the specified output file in DER format
                    with open(der_output, 'wb') as der_file:
                        der_file.write(extracted_public_key)
                        logger.info(f'Writing public key to {args.output_path}.der in DER format')
                       
                                                     
                    # Write the public key to the specified output file in PEM format                      
                    with open(pem_output, 'wb') as pem_file:
                        # Convert the public key to PEM format and save it to a file. 
                        pem_bytes = pem.armor('PUBLIC KEY', extracted_public_key)
                        pem_file.write(pem_bytes)
                        logger.info(f'Writing public key to {args.output_path}.pem in PEM format')  
                        time.sleep(1)
                        logger.info("Public key extraction completed.")    

     