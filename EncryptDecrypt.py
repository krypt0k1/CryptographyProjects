# Custom module to perform Encryption and Decryption operations using PKCS#11 within an nCipher Hardware Security Module (HSM).
# Tested and validated on nCipher nShield HSM 5c.
# Developed by Armando Montero.

import logging
import pkcs11 
from pkcs11 import MGF, Mechanism, Attribute, ObjectClass
from time import sleep
from Arguments import *
from ManagementOperations import *


# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "Encryption/Decryption  ")


args = Arguments().parse()
# Class for managing values

class EncryptDecrypt:
    def __init__(self, lib_path, token_label, pin, key_label,input_path, output_path, algorithm, iv):
        self.lib_path = lib_path
        self.token_label = token_label
        self.pin = pin
        self.key_label = key_label
        self.input_path = input_path
        self.output_path = output_path
        self.algorithm = algorithm        
        self.iv = iv        
        
   
        
    # Encrypt data
    def encrypt(self, args):
        # Load the PKCS#11 library
        lib = pkcs11.lib(self.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")

         # Load the HSM token
        token = lib.get_token(token_label=self.token_label)
        logger.info(f"Token label: {self.token_label} loaded successfully")
        sleep(1)
        logger.info(f"Opening session with token: {self.token_label}")
        sleep(1)

         # Open a session
        session = self.session = token.open(rw=True, user_pin=self.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # Find the key
        if args.algorithm in ["AES", "3DES"]:
            key = session.get_key(label=self.key_label)
            logger.info(f"Secret key label: {self.key_label} found in token label: {self.token_label}")
            sleep(3)

        if args.algorithm == "RSA":
        # Adjusted for RSA to correctly use the mechanism for public key retrieval
            key_iter = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.LABEL: self.key_label})
            key = list(key_iter)  # Convert the SearchIter object to a list
            logger.info(f'Public key label: {self.key_label} found in token label: {self.token_label}')
            sleep(3)

        # Generate a random IV
        iv = session.generate_random(args.iv)

        # Buffer size for chunked reading/writing
        buffer_size = 8192

        # Open input and output files with context managers
        logger.info(f"Opening input file: {self.input_path} to encrypt...")
        with open(self.input_path, "rb") as input_file, open(self.output_path, "wb") as output_file:
    
    # Read, encrypt, and write in chunks for stream ciphers like AES and 3DES
            while True:
                chunk = input_file.read(buffer_size)
                if not chunk:
                    break  

                if args.algorithm == "AES":
                    encrypted = key.encrypt(chunk, mechanism= Mechanism.AES_CBC_PAD, mechanism_param=iv)
                    logger.info("Encrypting data....")
                    sleep(8)

                    # Write the encrypted data to the output file
                    output_file.write(encrypted)
                    logger.info(f"Data encrypted using key label: {self.key_label} from token label: {self.token_label} successfully saved to {self.output_path}")
                    sleep(1)
                if args.algorithm == "3DES":
                    # Encrypt the data using 3DES
                    encrypted = key.encrypt(chunk, mechanism= Mechanism.DES3_CBC_PAD, mechanism_param=iv)
                    logger.info("Encrypting data....")
                    sleep(8)

                    # Write the encrypted data to the output file
                    output_file.write(encrypted)
                    logger.info(f"Data encrypted using key label: {self.key_label} from token label: {self.token_label} successfully saved to {self.output_path}")
                    sleep(1)     

                if args.algorithm == "RSA":
                    # For RSA, typically the whole data is encrypted at once due to block size limits
                    data = input_file.read()
                    encrypted = key[0].encrypt(data, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
                    logger.info("Encrypting data....")
                    sleep(8)

                    # Write the encrypted data to the output file
                    output_file.write(encrypted)
                    logger.info(f"Data encrypted using key label: {self.key_label} from token label: {self.token_label} successfully saved to {self.output_path}")
                    sleep(1)
                
            # Close the session
                session.close()
                logger.info(f"Session successfully closed!")

    def decrypt(self, args):
         # Load the PKCS#11 library
        lib = pkcs11.lib(self.lib_path)
        logger.info(f"PKCS#11 library loaded successfully")

         # Load the HSM token
        token = lib.get_token(token_label=self.token_label)
        logger.info(f"Token label: {self.token_label} loaded successfully")
        sleep(1)
        logger.info(f"Opening session with token: {self.token_label}")
        sleep(1)

         # Open a session
        session = self.session = token.open(rw=True, user_pin=self.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # Find the key
        if args.algorithm in ["AES", "3DES"]:
            key = session.get_key(label=self.key_label)
            logger.info(f"Secret key label: {self.key_label} found in token label: {self.token_label}")
            sleep(3)
        
        if args.algorithm == "RSA":
        # Adjusted for RSA to correctly use the mechanism for private key retrieval
            key_iter = session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: self.key_label})
            key = list(key_iter)  # Convert the SearchIter object to a list
            logger.info(f'Public key label: {self.key_label} found in token label: {self.token_label}')
            sleep(3)


        # Read the IV
        if args.algorithm == "AES":
            iv =  open(self.input_path, "rb").read(16) # 16 bytes for AES IV due to 128 bit block size 
            logger.info(f"AES algorithm detected. Reading IV from {self.input_path}...")
            sleep(3)

        if args.algorithm == "3DES": # 8 bytes for 3DES IV due to 64 bit block size
            iv = open(self.input_path, "rb").read(8)
            logger.info(f"3DES algorithm detected. Reading IV from {self.input_path}...")
            sleep(3)

            

        # Buffer size for chunked reading/writing
        buffer_size = 8192

        # Open input and output files with context managers
        with open(self.input_path, "rb") as input_file, open(self.output_path, "wb") as output_file:
            logger.info(f"Opening input file: {self.input_path} for decryption")

            if args.algorithm == "AES":
                # Read, decrypt, and write in chunks for stream ciphers like AES and 3DES
                while True:
                    chunk = input_file.read(buffer_size)
                    if not chunk:
                        break
                    decrypted = key.decrypt(chunk, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
                    output_file.write(decrypted)
                    logger.info("Decrypting data...")
                    sleep(8)
            
            if args.algorithm == "3DES":
                # Read, decrypt, and write in chunks for stream ciphers like AES and 3DES
                while True:
                    chunk = input_file.read(buffer_size)
                    if not chunk:
                        break
                    decrypted = key.decrypt(chunk, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
                    output_file.write(decrypted)
                    logger.info("Decrypting data...")
                    sleep(8)
                    logger.info(f"Data successfully decrypted using key label: {self.key_label} from token label: {self.token_label} saved to {self.output_path}")
                   
                    
            if args.algorithm == "RSA":
                # For RSA, typically the whole data is encrypted at once due to block size limits
                data = input_file.read()
                decrypted = key[0].decrypt(data, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
                output_file.write(decrypted)                
                logger.info(f"Data decrypted using key label: {self.key_label} from token label: {self.token_label} successfully saved to {self.output_path}")
                sleep(1)

        # Close the session        
        session.close()
        logger.info(f"Session successfully closed!")
