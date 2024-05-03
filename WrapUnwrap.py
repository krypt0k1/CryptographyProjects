# Class to manage Wrapping and Unwrapping of keys using PKCS11.
# This class leverages python-pkcs11 wrapper to interact with PKCS11 libraries.

import pkcs11
from pkcs11 import ObjectClass, KeyType
from Arguments import *
from Templates import *
from time import sleep
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := " Wrapping/Unwrapping  ")


# Create an instance of the Arguments class to parse the arguments.
args = Arguments().parse()

# Class to wrap and unwrap keys.
class WrapUnwrap:
    def __init__(self, wrap, unwrap):
        self.wrap = wrap
        self.unwrap = unwrap   

    def wrap_key(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully.")

        # Load the token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {args.token_label} loaded successfully.")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully.")
        sleep(1)

        if args.algorithm in ["AES", "3DES"]:       
        # Find the key
         wrapping_key = session.get_key(label=args.wrapping_key)
         key_to_be_wrapped = session.get_key(label=args.key_to_wrap)
         logger.info(f"Wrapping Key {wrapping_key.label} will wrap {key_to_be_wrapped.label} both keys are stored  in token: {token.label}.")
         sleep(1)

        elif args.algorithm in ["RSA", "DSA", "EC"]:
        # Find the public key
         wrapping_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=args.wrapping_key)
         logger.info(f"Key found: {wrapping_key.label} in token: {token.label}.")
         sleep(1)

        
        # Wrap the key
        wrapped_key = wrapping_key.wrap_key(key_to_be_wrapped, mechanism=None, mechanism_param=None)
        logger.info(f"Key wrapping operation successful!")

            # Save the wrapped key to a file
        with open(args.output_path, 'wb') as wrapped_key_file:
            wrapped_key_file.write(wrapped_key)
            logger.info(f"Wrapped key written to: {args.output_path}.")
            sleep(1)

        # Close the session
        session.close()
        logger.info(f"Session closed successfully.")
        
    def unwrap_key(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully.")
        sleep(1)
        # Load the token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {args.token_label} loaded successfully.")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully.")
        sleep(1)

        # Define the data to unwrap
        key_data = open(args.input_path, 'rb').read()
        # Condition to check if the key is a secret key or a public key and its key type.
        if args.algorithm in ["AES"]:

            object_class = ObjectClass.SECRET_KEY
            key_type = KeyType.AES

            if args.attribute == None:
                template = default_aes_template
            else:
                template = aes_template

        elif args.algorithm in ["3DES"]:

            object_class = ObjectClass.SECRET_KEY
            key_type = KeyType.DES3
            
        elif args.algorithm in ["RSA"]:            
            object_class = ObjectClass.PUBLIC_KEY
            key_type = KeyType.RSA

            if args.attribute == None:
                template = default_rsa_public_template
            else:
                template = public_rsa_key_template


        elif args.algorithm in ["DSA"]:
            object_class = ObjectClass.PUBLIC_KEY
            key_type = KeyType.DSA
            template = None

        elif args.algorithm in ["EC"]:
            object_class = ObjectClass.PUBLIC_KEY
            key_type = KeyType.EC
            template = None


        # Find the wrapping/unwrapping key
        key = session.get_key(label=args.wrapping_key, object_class= object_class)
        logger.info(f"Key found: {key.label} in token: {token.label}.")
        sleep(1)

        # Verify if the new label exist in token.
        if args.new_label in session.get_key(label = args.new_label, object_class= object_class):
            logger.error(f"Key label: ' {args.new_label} 'already exists in token: {token.label}.")
            logger.error(f"Please choose a different label.")

            # Close the session
            session.close()
            logger.info(f"Session closed successfully.")
            exit(1)
        else:
            # Unwrap the key material 
            unwrapped_key = key.unwrap_key(object_class = object_class, key_type = key_type, mechanism= None, 
                                                        mechanism_param=None, 
                                                        key_data = key_data,
                                                        label=args.new_label, 
                                                        store=True,
                                                        template= template)
            logger.info(f"Key unwrapped successfully!")
            logger.info(f'Unwrapped key: {unwrapped_key.label}. placed in {token.label} token.')
            sleep(1)

        # Close the session
        session.close()
        logger.info(f"Session closed successfully.")
        exit(1)