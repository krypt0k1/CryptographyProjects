
# Program for encryption & decryption cryptographic operations using a nCipher nShield HSM. 
# Supports AES, 3DES, and RSA algorithms.
# Tested and validated on nCipher nShield HSM 5c. Works on any nShield HSM product line. 
# Developed by Armando Montero

import argparse
import logging
import pkcs11 
from pkcs11 import MGF, Mechanism, Attribute, ObjectClass
from time import sleep

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "cryptops")


# Class for managing keys and cryptographic operations

class KeyManager:
    def __init__(self, lib_path, token_label, pin, key_label,input_path, output_path, algorithm, mechanism, iv):
        self.lib_path = lib_path
        self.token_label = token_label
        self.pin = pin
        self.key_label = key_label
        self.input_path = input_path
        self.output_path = output_path
        self.algorithm = algorithm
        self.mechanism = mechanism
        self.iv = iv 
        self.session = self.open_session()


        
    @staticmethod
    def args():
        
        parser = argparse.ArgumentParser(description="Encrypt or decrypt data using a nCipher nShield HSM", 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter, 
        epilog="Developed by Armando Montero", 
        prog="cryptops.py", 
        usage="python3 cryptops.py -e <encrypt>-l <lib_path> -t <token_label> -p <pin> -k <key_label> -i <input_path> -o <output_path> -a <algorithm> -m <mechanism> -iv <iv> ", 
        prefix_chars="-", 
        add_help=True, 
        allow_abbrev=True)
        parser.add_argument("-l", "--lib_path", type=str, help="Path to the PKCS#11 library", 
                            default="/opt/nfast/toolkits/pkcs11/libcknfast.so")
        parser.add_argument("-t", "--token_label", type=str, help="Label of the token",
                            default="loadshared accelerator")
        parser.add_argument("-p", "--pin", type=str, help="PIN of the token", default="123456")
        parser.add_argument("-k", "--key_label", type=str, help="Label of the key")
        parser.add_argument("-i", "--input_path", type=str, help="Path to the input file")
        parser.add_argument("-o", "--output_path", type=str, help="Path to the output file")
        parser.add_argument("-a", "--algorithm", type=str, help="Algorithm to use", default="AES")
        parser.add_argument("-m", "--mechanism", type=str, help="Mechanism to use", default="AES_CBC_PAD")
        parser.add_argument("-iv", "--iv", type=int, help="Initialization vector", default = 128)
        parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the data")
        parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the data")


        args = parser.parse_args()
        return args

    # Session management.

    # Open a session
    def open_session(self):
        lib = pkcs11.lib(self.lib_path)
        token = lib.get_token(token_label=self.token_label)
        session = token.open(rw=True, user_pin=self.pin)
        return session
    
    # Close a session
    def close_session(self):
        self.session.close()
        
    # Encrypt data
    def encrypt(self, args):
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
        session = self.session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # Find the key
        if args.algorithm in ["AES", "3DES"]:
            key = session.get_key(label=args.key_label)
            logger.info(f"Secret key label: {args.key_label} found in token label: {args.token_label}")
            sleep(3)

        if args.algorithm == "RSA":
        # Adjusted for RSA, ECC to correctly use the mechanism for public key retrieval
            key_iter = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.LABEL: args.key_label})
            key = list(key_iter)  # Convert the SearchIter object to a list
            logger.info(f'Public key label: {args.key_label} found in token label: {args.token_label}')
            sleep(3)

        # Generate a random IV
        iv = session.generate_random(args.iv)

        # Buffer size for chunked reading/writing
        buffer_size = 8192

        # Open input and output files with context managers
        logger.info(f"Opening input file: {args.input_path} to encrypt...")
        with open(args.input_path, "rb") as input_file, open(args.output_path, "wb") as output_file:
    
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
                    logger.info(f"Data encrypted using key label: {args.key_label} from token label: {args.token_label} successfully saved to {args.output_path}")
                    sleep(1)
                if args.algorithm == "3DES":
                    # Encrypt the data using 3DES
                    encrypted = key.encrypt(chunk, mechanism= Mechanism.DES3_CBC_PAD, mechanism_param=iv)
                    logger.info("Encrypting data....")
                    sleep(8)

                    # Write the encrypted data to the output file
                    output_file.write(encrypted)
                    logger.info(f"Data encrypted using key label: {args.key_label} from token label: {args.token_label} successfully saved to {args.output_path}")
                    sleep(1)     

                if args.algorithm == "RSA":
                    # For RSA, typically the whole data is encrypted at once due to block size limits
                    data = input_file.read()
                    encrypted = key[0].encrypt(data, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
                    logger.info("Encrypting data....")
                    sleep(8)

                    # Write the encrypted data to the output file
                    output_file.write(encrypted)
                    logger.info(f"Data encrypted using key label: {args.key_label} from token label: {args.token_label} successfully saved to {args.output_path}")
                    sleep(1)
                
            # Close the session
                self.close_session()
                logger.info(f"Session successfully closed!")

    def decrypt(self, args):
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
        session = self.session = token.open(rw=True, user_pin=args.pin)
        logger.info(f"Session opened successfully")
        sleep(1)

        # Find the key
        if args.algorithm in ["AES", "3DES"]:
            key = session.get_key(label=args.key_label)
            logger.info(f"Secret key label: {args.key_label} found in token label: {args.token_label}")
            sleep(3)
        
        if args.algorithm == "RSA":
        # Adjusted for RSA, ECC to correctly use the mechanism for public key retrieval
            key_iter = session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: args.key_label})
            key = list(key_iter)  # Convert the SearchIter object to a list
            logger.info(f'Public key label: {args.key_label} found in token label: {args.token_label}')
            sleep(3)


        # Read the IV
        if args.algorithm == "AES":
            iv =  open(args.input_path, "rb").read(16) # 16 bytes for AES IV due to 128 bit block size 
            logger.info(f"AES algorithm detected. Reading IV from {args.input_path}...")
            sleep(3)

        if args.algorithm == "3DES": # 8 bytes for 3DES IV due to 64 bit block size
            iv = open(args.input_path, "rb").read(8)
            logger.info(f"3DES algorithm detected. Reading IV from {args.input_path}...")
            sleep(3)

            

        # Buffer size for chunked reading/writing
        buffer_size = 8192

        # Open input and output files with context managers
        with open(args.input_path, "rb") as input_file, open(args.output_path, "wb") as output_file:
            logger.info(f"Opening input file: {args.input_path} for decryption")

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
                    logger.info("Data successfully decrypted using key label: {args.key_label} from token label: {args.token_label} saved to {args.output_path}")
                   
                    
            if args.algorithm == "RSA":
                # For RSA, typically the whole data is encrypted at once due to block size limits
                data = input_file.read()
                decrypted = key[0].decrypt(data, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
                output_file.write(decrypted)                
                logger.info(f"Data decrypted using key label: {args.key_label} from token label: {args.token_label} successfully saved to {args.output_path}")
                sleep(1)

        # Close the session        
        self.close_session()
        logger.info(f"Session successfully closed!")


# Main function
def main():
    args = KeyManager.args() # Parse the arguments
    km = KeyManager(lib_path=args.lib_path, token_label=args.token_label, pin=args.pin, key_label=args.key_label, input_path=args.input_path, output_path=args.output_path, algorithm=args.algorithm, mechanism=args.mechanism, iv=args.iv)

    if args.encrypt:
        km.encrypt(args)

    if args.decrypt:
        km.decrypt(args)


if __name__ == "__main__":
    try:
        main()

    # Handle exceptions    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
    except pkcs11.exceptions.FunctionFailed:
        logger.error("Function failed. Check the input parameters.")
    except pkcs11.exceptions.MechanismInvalid:
        logger.error("Invalid mechanism. Check the input parameters.")
    except pkcs11.exceptions.MechanismParamInvalid:
        logger.error("Invalid mechanism parameter. Check the input parameters.")
    except pkcs11.exceptions.ObjectNotFound:
        logger.error("Object not found. Check the input parameters.")
    except pkcs11.exceptions.PinExpired:
        logger.error("Incorrect PIN. Check the input parameters.")
    except pkcs11.exceptions.PinInvalid:
        logger.error("Invalid PIN.")
    except pkcs11.exceptions.TokenNotFound:
        logger.error("Token not found. Check the input parameters.")
    except pkcs11.exceptions.TokenNotPresent:
        logger.error("Token not present. Check the input parameters.")
    except pkcs11.exceptions.UserAlreadyLoggedIn:
        logger.error("User already logged in. Reset the token/ session.")
    except pkcs11.exceptions.UserNotLoggedIn:
        logger.error("User not logged in.")
    except pkcs11.exceptions.SessionHandleInvalid:
        logger.error("Session handle invalid.")
   
        exit(1)
