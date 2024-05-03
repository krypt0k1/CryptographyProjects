# Program to manage a robust PKCS#11 infrastructure using nCipher nShield HSM. 
# Designed to perform various management operations such as encryption, decryption, wrapping, unwrapping, generating, copying, deleting keys and more.
# Supports AES, 3DES, DSA, and EC algorithms.
# Tested and validated on nCipher nShield HSM 5c. 
# Developed by Armando Montero.
# Modules used: Custom modules EncryptDecrypt, Arguments, SignVerify, Templates, ManagementOperations, WrapUnwrap, ImportExport which leverage pkcs11, logging, argparse, time, os modules.

from EncryptDecrypt import *
from Arguments import *
from ManagementOperations import *
from SignVerify import *
from WrapUnwrap import *
from Export import *
import logging
import pyfiglet

# Configure logging
logging.basicConfig(level=logging.INFO, format=" %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "p11-tool")


def main():

# Create instances of the classes.
    args = Arguments().parse()
    crypt = EncryptDecrypt(args.lib_path, args.token_label, args.pin, args.key_label, args.input_path, args.output_path, args.algorithm, args.iv)
    manage = ManagementOperations(args.generate, args.copy, args.delete, args.list, args.find)
    sign_ver = SignVerify(args.sign, args.verify)
    wrapping_ops = WrapUnwrap(args.wrap, args.unwrap)
    export = Export(args.export_key)

    # Perform the operation based on the arguments.
    if args.generate:
        manage.generate_keys(args)
    elif args.copy:
        manage.copy_keys(args)
    elif args.delete:
        manage.delete_keys(args)
    elif args.list_keys:
        manage.list_keys(args)
    elif args.list_tokens:
        manage.list_tokens(args)
    elif args.find_token:
        manage.find_token(args)
    elif args.encrypt:
        crypt.encrypt(args)
    elif args.decrypt:
        crypt.decrypt(args)    
    elif args.sign:  
        sign_ver.sign_data(args)
    elif args.verify:
        sign_ver.verify_data(args)
    elif args.wrap:
        wrapping_ops.wrap_key(args)
    elif args.unwrap:
        wrapping_ops.unwrap_key(args)    
    elif args.export_key:
        export.export_pub_key(args)
    else:
        error = "No operation specified. Use --encrypt, --decrypt, --sign, --verify, --wrap, --unwrap, --export, --generate, --copy, --delete, --list-tokens, or --find-token. and its respective arguments. See --help for more information."
        banner = pyfiglet.figlet_format('p 11-tool', font = 'alligator2')
        epilog= "Developed by Armando Montero."
        print(banner)
        print(epilog)
        print(error)        
        exit(1)

# Call to program.
if __name__ == "__main__":
    try:
        main() 

    # Handle exceptions    

    # File Exception
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")

    # Operations, Argument Exceptions
    except pkcs11.FunctionFailed:
        logger.error("Function failed. Check the input parameters.")
    except pkcs11.MechanismInvalid:
        logger.error("Invalid mechanism. Check the input parameters.")
    except pkcs11.MechanismParamInvalid:
        logger.error("Invalid mechanism parameter. Check the input parameters.")
    except pkcs11.ObjectHandleInvalid:
        logger.error("Object not found. Check the input parameters.")
    except pkcs11.ArgumentsBad:
        logger.error("Arguments are invalid. Check the input parameters.")

    # Session, Token, User and Pin Exceptions
    except pkcs11.PinExpired:
        logger.error("PIN has expired. Change the pin or check the input parameters.")
    except pkcs11.PinInvalid:
        logger.error("Invalid PIN.")  
    except pkcs11.TokenNotPresent:
        logger.error("Token not present. Check the input parameters.")
    except pkcs11.UserAlreadyLoggedIn:
        logger.error("User already logged in. Reset the token/ session.")
    except pkcs11.UserNotLoggedIn:
        logger.error("User not logged in.")
    except pkcs11.SessionHandleInvalid:
        logger.error("Session handle invalid.")
    except pkcs11.SessionReadOnly:
        logger.error("Session read-only.")
    except pkcs11.SessionExists:
        logger.error("Session already exists")    
    except pkcs11.DeviceRemoved:
        logger.error("Phyisical Token removed or softcard unloaded from memory")
    except pkcs11.DeviceError:
        logger.error("Device error, check logs.") 
  
    

     # Key Exceptions
    except pkcs11.WrappingKeyHandleInvalid:
        logger.error("Wrapping key handle invalid.")
    except pkcs11.WrappedKeyInvalid:
        logger.error("Wrapped key invalid.")
    except pkcs11.WrappedKeyLenRange:
        logger.error("Wrapped key length out of range.")
    except pkcs11.KeyNotWrappable:   
        logger.error("Key not wrappable.")
    except pkcs11.WrappingKeyTypeInconsistent:
        logger.error("Wrapping key type inconsistent.")
    except pkcs11.KeyTypeInconsistent:
        logger.error("Key type inconsistent.")
    except pkcs11.KeyHandleInvalid:
        logger.error("Key handle invalid.")
    except pkcs11.KeySizeRange:
        logger.error("Key size out of range.")
    except pkcs11.KeyUnextractable:
        logger.error("Key unextractable. Must have CKA_EXTRACTABLE set to True.")
    except pkcs11.NoSuchKey:
        logger.error("Key not found.")
    
        # Encryption Errors
    except pkcs11.EncryptedDataInvalid:
        logger.error("Encrypted data invalid.")
    except pkcs11.EncryptedDataLenRange:
        logger.error("Encrypted data length out of range.")
    except pkcs11.DataInvalid:
        logger.error("Data invalid.")
    except pkcs11.DataLenRange:
        logger.error("Data length out of range.")  
    
    # Signing and verification errors
    except pkcs11.SignatureInvalid:
        logger.error("Signature invalid.")
    except pkcs11.SignatureLenRange:
        logger.error("Signature length out of range.") 
   
        exit(1)