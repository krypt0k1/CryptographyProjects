# Class to Sign and Verify a message. 
# Tested and validated on nCipher nShield HSM 5c.
# Developed by Armando Montero.

import datetime
import logging
from time import sleep
import pkcs11
from Arguments import *


# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "Sign/Verify  ")

# Call the Arguments class to parse the arguments
args = Arguments().parse()

class SignVerify:
    def __init__(self, sign, verify):
        self.sign = sign
        self.verify = verify
        
            
    def sign_data(self, lib, args):
        # Init the library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f'PKCS#11 library loaded successfully.')
        sleep(1)

        # Load the token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f'Token label: {args.token_label} loaded successfully.')
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)   
        logger.info(f'Session opened successfully.')
        sleep(1)

       # Define data to sign.
        data = open(args.input_path, 'rb').read()

        # Find the key
        if args.algorithm in ["AES", "3DES"]: 
            key = session.get_key(label=args.key_label)
            logger.info(f'Key found: {key.label} in token: {token.label}.')
            sleep(1)

            # Sign the data
            signature = key.sign(data)
            logger.info(f'Successfully signed: {signature.hex()} in hex format.')

        elif args.algorithm in ["RSA", "DSA", "EC"]:
            # Find the public key
            private_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=args.key_label)
            # Sign the data
            signature = private_key.sign(data)
            logger.info(f'File successfully signed: {signature.hex()} (in hex format).')  
            sleep(1)

        # Save the signature to a file
        with open(args.output_path, 'wb') as sig_file:
            sig_file.write(signature)
            logger.info('Signature saved under ' + args.output_path + ' (in byte format).' )
            sleep(1)
    
    def verify_data(self, args):
        # Init the library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f'PKCS#11 library loaded successfully.')
        sleep(1)
        
        # Load the token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f'Token label: {args.token_label} loaded successfully.')
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)   
        logger.info(f'Session opened successfully.')
        sleep(1)

        # Define data to verify.
        data = open(args.input_path, 'rb').read()
        signature = open(args.signature_path, 'rb').read()

        # Find the key
        if args.algorithm in ["AES", "3DES"]: 
            key = session.get_key(label=args.key_label)
            logger.info(f'Key found: {key.label} in token: {token.label}.')
            
            # Verify the signature
            verification = key.verify(data, signature)
            if verification is True:
                logger.info(f'Signature verified successfully using key: {key.label}')
            else:
                logger.error(f'Signature verification failed using key: {key.label}')

        elif args.algorithm in ["RSA", "DSA", "EC"]:
            # Find the key
            public_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=args.key_label)
            logger.info(f'Public key found: {public_key.label} in token: {token.label}.')
            sleep(1)

            # Verify the signature
            verification = public_key.verify(data, signature)

            if verification is True:
                logger.info(f'Signature verified successfully using public key: {public_key.label}')
            else:
                logger.error(f'Signature verification failed using public key: {public_key.label}')

        else:
            logger.error("Invalid algorithm. Check the input parameters.")
            exit(1)



    