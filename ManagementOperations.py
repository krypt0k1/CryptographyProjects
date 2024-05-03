# Description: This file contains the ManagementOperations class which is responsible for generating, copying, deleting, listing keys and tokens, and finding tokens.
# The class is called from the main function in p11-tool.py to perform the management operations.
# The class uses the pkcs11 library to interact with the nCipher HSM. Arguments class to parse the arguments passed to the program. Templates module to pass stored values from templates for the keys,
# logging module to log messages to the console, and the sleep function from the time module to pause the program for a specified amount of time.

import logging
import pkcs11 
from pkcs11 import KeyType, Attribute, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters
from time import sleep
from Arguments import *
from Templates import *


# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "Management Operations")

# Call the Arguments class to parse the arguments
args = Arguments().parse() # type: ignore

class ManagementOperations:
    def __init__(self, generate, copy, delete, list, find):
        self.generate = generate
        self.copy = copy
        self.delete = delete
        self.list = list
        self.find = find


    def generate_keys(self,args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")

        # Load the HSM token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {args.token_label} loaded successfully")
        sleep(1)
        logger.info(f"Opening session with token: {args.token_label}")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # Generate a key 
        if args.algorithm in ["AES"]:
              # Try to find the key
            try:
             key = session.get_key(label=args.key_label)
             logger.info(f"Key with label: {key.label} found. Cancelling operation.")
             exit(1)
            except pkcs11.exceptions.NoSuchKey:
                logger.info(f"No key matching label: {args.key_label}. Continuing with key generation....")
                
                # Check if the user set any attributes. If not, use the default template.
                if args.attribute is None:
                    template = default_aes_template
                else:
                    template = aes_template
                
                # Generate the key
                key = session.generate_key(key_type= KeyType.AES, key_length= args.key_length, mechanism= None, label=args.key_label, store= True, template = template)
                logger.info(f"AES Key generated with label: {key.label} and length: {key.key_length}, stored in the token label: {token.label} successfully!")

                key_info = {"LABEL": key.__getitem__(pkcs11.Attribute.LABEL),
                            "TOKEN": key.__getitem__(pkcs11.Attribute.TOKEN),
                            "KEY TYPE": key.__getitem__(pkcs11.Attribute.KEY_TYPE),
                            "KEY SIZE": key.__getitem__(pkcs11.Attribute.VALUE_LEN),
                            "TRUSTED": key.__getitem__(pkcs11.Attribute.TRUSTED),
                            "PRIVATE": key.__getitem__(pkcs11.Attribute.PRIVATE),
                            "MODIFIABLE": key.__getitem__(pkcs11.Attribute.MODIFIABLE),
                            "SENSITIVE": key.__getitem__(pkcs11.Attribute.SENSITIVE),
                            "EXTRACTABLE": key.__getitem__(pkcs11.Attribute.EXTRACTABLE),
                            "WRAP WITH TRUSTED": key.__getitem__(pkcs11.Attribute.WRAP_WITH_TRUSTED),
                            "ENCRYPT": key.__getitem__(pkcs11.Attribute.ENCRYPT),
                            "DECRYPT": key.__getitem__(pkcs11.Attribute.DECRYPT),
                            "WRAP": key.__getitem__(pkcs11.Attribute.WRAP),
                            "UNWRAP": key.__getitem__(pkcs11.Attribute.UNWRAP),
                            "SIGN": key.__getitem__(pkcs11.Attribute.SIGN),
                            "VERIFY": key.__getitem__(pkcs11.Attribute.VERIFY)}
               
                    
                for key, value in key_info.items():
                    if "KEY SIZE" == 32:
                        logger.info(f"{key}: 256 bits")
                    if "KEY TYPE" == 31:
                        logger.info(f"{key}: AES")
                        
                    logger.info(f"{key}: {value}")

                if args.key_length < 128:
                    logger.error("AES key length must be at least 128 bits with a maximum of 256 bits")
                    exit(1)
        
        elif args.algorithm in ["3DES"]:
                # Check if key exists prior to generating a new key.

                if key := session.get_key(label=args.key_label):
                    logger.error(f"Key with label: {args.key_label} already exists. Please choose a different label.")
                    exit(1)
                else:
                    logger.info(f"Key with label: {args.key_label} not found. Generating a new key...")
                    sleep(1)
            # Generate the key
                key = session.generate_key(key_type= KeyType.DES3, key_length= args.key_length, mechanism= None, label=args.key_label, store= True, template = None)
                logger.info(f" DES3 Key generated with label: {key.label} and length: {key.key_length}, stored in the token label: {token.label} successfully!")

                key_info = {"LABEL": key.__getitem__(pkcs11.Attribute.LABEL),
                            "TOKEN": key.__getitem__(pkcs11.Attribute.TOKEN),
                            "KEY TYPE": key.__getitem__(pkcs11.Attribute.KEY_TYPE),
                            "KEY SIZE": key.__getitem__(pkcs11.Attribute.VALUE_LEN),
                            "TRUSTED": key.__getitem__(pkcs11.Attribute.TRUSTED),
                            "PRIVATE": key.__getitem__(pkcs11.Attribute.PRIVATE),
                            "MODIFIABLE": key.__getitem__(pkcs11.Attribute.MODIFIABLE),
                            "SENSITIVE": key.__getitem__(pkcs11.Attribute.SENSITIVE),
                            "EXTRACTABLE": key.__getitem__(pkcs11.Attribute.EXTRACTABLE),
                            "WRAP WITH TRUSTED": key.__getitem__(pkcs11.Attribute.WRAP_WITH_TRUSTED),
                            "ENCRYPT": key.__getitem__(pkcs11.Attribute.ENCRYPT),
                            "DECRYPT": key.__getitem__(pkcs11.Attribute.DECRYPT),
                            "WRAP": key.__getitem__(pkcs11.Attribute.WRAP),
                            "UNWRAP": key.__getitem__(pkcs11.Attribute.UNWRAP),
                            "SIGN": key.__getitem__(pkcs11.Attribute.SIGN),
                            "VERIFY": key.__getitem__(pkcs11.Attribute.VERIFY)}
               

                for key in key_info:
                    if "KEY SIZE" == 24:
                        logger.info(f"{key}: 192 bits")
                    if "KEY TYPE" == 30:
                        logger.info(f"{key}: 3DES")
                        
                    logger.info(f"{key}: {value}")
                sleep(1)

                if args.key_length < 128:
                    logger.error("3DES key length must be at least 128 bits with a maximum of 192 bits")
                    exit(1)

        elif args.algorithm in ["RSA"]:  
                # Check if key exists prior to generating a new key.
                try:
                    public_key = session.get_key(label = args.key_label, object_class=ObjectClass.PUBLIC_KEY)                    
                    logger.error(f"Public/Private key pair with label: {public_key.label} already exists. Please choose a different label.")
                    exit(1)
                except pkcs11.exceptions.NoSuchKey:
                    logger.info(f"Public/Private key pair with label: {args.key_label} not found. Generating a new key...")
                    sleep(1)
                # Generate the key             
                
                # Check if the user set any attributes. If not, use the default template.
                if args.attribute is None:
                    public_template = default_rsa_public_template
                    private_template = default_rsa_private_template
                else:
                    public_template = public_rsa_key_template
                    private_template = private_rsa_key_template
                         
                public, private = session.generate_keypair(key_type= KeyType.RSA, mechanism = None, key_length= args.key_length, label=args.key_label, store= True, 
                                                                    public_template = public_template, private_template = private_template)
                logger.info(f"RSA Key Pair generated with label: {public.label} and length: {public.key_length}, stored in the token label: {token.label} successfully!")

                pub_key_info = {"LABEL": public.__getitem__(pkcs11.Attribute.LABEL),
                            "TOKEN": public.__getitem__(pkcs11.Attribute.TOKEN),
                            "KEY TYPE": public.__getitem__(pkcs11.Attribute.KEY_TYPE),
                            "KEY SIZE": public.__getitem__(pkcs11.Attribute.MODULUS_BITS),
                            "TRUSTED": public.__getitem__(pkcs11.Attribute.TRUSTED),
                            "PRIVATE": public.__getitem__(pkcs11.Attribute.PRIVATE),
                            "MODIFIABLE": public.__getitem__(pkcs11.Attribute.MODIFIABLE),                      
                            "ENCRYPT": public.__getitem__(pkcs11.Attribute.ENCRYPT),                        
                            "WRAP": public.__getitem__(pkcs11.Attribute.WRAP),                         
                            "VERIFY": public.__getitem__(pkcs11.Attribute.VERIFY)}
               
                print("Public Key Info:") 
                for public, value in pub_key_info.items():                 
                    logger.info(f"{public}: {value}")              
                sleep(1)
                        
                priv_key_info = {
                            "LABEL": private.__getitem__(pkcs11.Attribute.LABEL),
                            "TOKEN": private.__getitem__(pkcs11.Attribute.TOKEN),
                            "KEY TYPE": private.__getitem__(pkcs11.Attribute.KEY_TYPE),
                            "KEY SIZE": private.__getitem__(pkcs11.Attribute.MODULUS_BITS),                            
                            "PRIVATE": private.__getitem__(pkcs11.Attribute.PRIVATE),
                            "MODIFIABLE": private.__getitem__(pkcs11.Attribute.MODIFIABLE),
                            "SENSITIVE": private.__getitem__(pkcs11.Attribute.SENSITIVE),
                            "EXTRACTABLE": private.__getitem__(pkcs11.Attribute.EXTRACTABLE),               
                            "DECRYPT": private.__getitem__(pkcs11.Attribute.DECRYPT),                            
                            "UNWRAP": private.__getitem__(pkcs11.Attribute.UNWRAP), 
                            "SIGN": private.__getitem__(pkcs11.Attribute.SIGN)
                            }                                                   
                            
                sleep(1)   
                                    
                print("Private Key Info:")

                for private, value in priv_key_info.items():                
                        logger.info(f"{private}: {value}")
                sleep(1)
                
                
                if args.key_length < 2048:
                    logger.error("RSA key length must be at least 2048 bits with a maximum of 4096 bits")
                    exit(1)

        elif args.algorithm  in ["DSA"]:
                try:   
                    public_key = session.get_key(label=args.key_label, object_class=ObjectClass.PUBLIC_KEY)
                    private_key = session.get_key(label=args.key_label, object_class=ObjectClass.PRIVATE_KEY)
                    logger.error(f"Public/Private key pair with label: {public_key.key_label} already exists. Please choose a different label.")
                    exit(1)
                except pkcs11.exceptions.NoSuchKey:
                    logger.info(f"Public/Private key pair with label: {args.key_label} not found. Generating a new key...")
                    sleep(1)
                    
                # Generate the key    
                parameters = session.generate_domain_parameters(KeyType.DSA, 1024)

                public, private = parameters.generate_keypair(label=args.key_label, store=True)
 
                logger.info(f"DSA Key Pair generated with label: {public.label} and length: 1024, stored in the token label: {token.label} successfully!")
                sleep(1)

        elif args.algorithm in ["EC"]:
               
               parameters = session.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(args.curve)}, local=True) # Requires local = True to create_domain_parameters
               public, private = parameters.generate_keypair(label=args.key_label, public_template = None, private_template = None, store=True)

               logger.info(f"EC Key Pair generated with label: {public.label} and curve: {args.curve}, stored in the token label: token.label successfully!")
               sleep(1)

        session.close()
        logger.info("Session successfully closed!")
       
    def copy_keys(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")
        sleep(1)

        # Load the HSM token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label:'{token.label}' loaded successfully")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully with slot: {token.label}")
        sleep(1)
         

        if args.algorithm in ["RSA", "DSA", "EC"]:
              # Find the keys
              public_key = session.get_key(label=args.key_label, object_class=ObjectClass.PUBLIC_KEY)
              private_key = session.get_key(label=args.key_label, object_class=ObjectClass.PRIVATE_KEY)
              logger.info(f"Public key with label: {public_key.label} and Private key with label: {private_key.label} found successfully!")
              
              # Copy the keys
              new_pub = public_key.copy({Attribute.LABEL: args.new_label})
              logger.info(f"Copying public key with label: {public_key.label} to new label: {args.new_label}...")
              sleep(1)
              
              new_priv = private_key.copy({Attribute.LABEL: args.new_label})
              logger.info(f"Copying private key with label: {private_key.label} to new label: {args.new_label}...")
              sleep(1)

              if new_pub.object_class == 2: # Per python-pkcs11 documentation, 2 is the object class for public keys
                    logger.info(f"Public key with label: {new_pub.label} copied successfully!")
              if new_priv.object_class == 3: # Per python-pkcs11 documentation, 3 is the object class for private keys
                    logger.info(f"Private key with label: {new_priv.label} copied successfully!")
        
        elif args.algorithm in ["AES", "3DES"]:
              key = session.get_key(label=args.key_label)
              logger.info(f"Key with label: {key.label} found successfully!")
              sleep(1)

                # Copy the key
              new_key = key.copy({Attribute.LABEL: args.new_label})
              logger.info(f"Copying key with label: {key.label} to new label: '{args.new_label}' ...")
                    
    
    def delete_keys(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")
        sleep(1)

        # Load the HSM token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {token.label} loaded successfully")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully")
        sleep(1)
        if args.algorithm in ["AES", "3DES"]:
            # Find the key
            if key := session.get_key(label=args.key_label):
                logger.info(f"Key with label: {key.label} found!")
                sleep(1)
                
                # Delete the key
                key.destroy()
                logger.info(f"Key with label: {key.label} deleted successfully!")
                sleep(1)
            else:
                logger.error(f"Key with label: {args.key_label} not found. Check the label parameters or your configuration file (cknfastrc).")
                exit(1)                           
        
        elif args.algorithm in ["RSA", "DSA", "EC"]:
        
            # Find the keys.
            if public_key := session.get_key(label=args.key_label, object_class=ObjectClass.PUBLIC_KEY):
                logger.info(f"Public key with label: {public_key.label} found!")
                sleep(1)
            if private_key := session.get_key(label=args.key_label, object_class=ObjectClass.PRIVATE_KEY):
                logger.info(f"Private key with label: {private_key.label} found!")
                sleep(1)

            # Delete the keys
            public_key.destroy()
            logger.info(f"Public key with label: {public_key.label} deleted successfully!")
            
            private_key.destroy()
            logger.info(f"Private key with label: {private_key.label} deleted successfully!")
        else:
            logger.error(f"Key with label: {args.key_label} not found. Check the label parameters or your configuration file (cknfastrc).")
            exit(1)


        # Close the session
        session.close()
        logger.info("Session successfully closed!")
    
    def list_keys(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")
        sleep(1)

        # Load the HSM token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {token.label} loaded successfully")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # List all keys
        logger.info(f"Listing all keys in token: {token.label}")
        for sec in session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}):
            if sec.key_type == 31 and sec.object_class == 4:
                logger.info(f"Secret key label: {sec.label} Algorithm: AES")
                
            
        
        for pub in session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}):
          
            if pub.key_type == 0:
                logger.info(f"Public/Private key pair label: {pub.label} Algorithm: RSA")
                pass
            if pub.key_type == 1:
                logger.info(f"Public/Private key pair label: {pub.label} Algorithm: DSA")
                pass
            if pub.key_type == 3:
                logger.info(f"Public/Private key pair label: {pub.label} Algorithm: EC")
                sleep(1)
 
    
        # Close the session
        session.close()
        logger.info("Session successfully closed!")

    # List all tokens
    def list_tokens(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")
        sleep(1)

        # List all tokens and order it by list
        
        logger.info("Listing all available tokens:")
        for slot in lib.get_slots():
            token = slot.get_token()
                     
            logger.info(f"Token label found!")
            sleep
            # Create a list of all tokens. 
            tokens = [] # Create an empty list
            tokens.append(token.label) # Append the token label to the list
            tokens.sort() # Sort the list. 

            logger.info(f"Token label: {tokens}")
            sleep(1)

    # Find a single token.
    def find_token(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully.")
        sleep(1)

        # Find a token
        if args.token_label:
            token = lib.get_token(token_label=args.token_label)
            logger.info(f"Token with label: {token.label} found!")
        else:
            logger.error(f"Token label: {token.label} not found. Check the label parameters or your configuration file (cknfastrc).")
            exit(1)
      
    # Modify an attribute of a key.
    def mod_attr(self, args):
         # Load the PKCS#11 library
        lib = pkcs11.lib(args.lib_path)
        logger.info(f"PKCS#11 library loaded successfully.")
        sleep(1)

        # Load the HSM token
        token = lib.get_token(token_label=args.token_label)
        logger.info(f"Token label: {token.label} loaded successfully.")
        sleep(1)

        # Open a session
        session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully.")
        sleep(1)

        # Find the key
        key = session.get_key(label=args.key_label)
        logger.info(f"Key with label: {key.label} found.")
        sleep(1)
        # TODO - Add code to modify the key attribute..

        # Close the session
        session.close()
        exit(1)
        

