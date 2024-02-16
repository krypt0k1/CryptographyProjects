# Description: This script is used to Encrypt & Decrypt using AES keys in an Entrust HSM.
import pkcs11
import argparse
import os
from rich import print
from rich.table import Table
from rich.console import Console
  
 
# Define the PKCS#11 DLL path
 
LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'),
                                  'toolkits', 'pkcs11', 'libcknfast.so')
lib = pkcs11.lib(LIB)
     
 
# Define environment variables.
os.environ["CKNFAST_LOADSHARING"] = "1"
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = "1"
 
 
 
# Define arguments.
def parse_args():
    """
    Parse command line arguments for the script.
 
    Returns:
        dict: A dictionary containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
            description="Entrust Python PKCS#11 Encryption & Decryption script.\n\n"
            "This script is used to encrypt and decrypt txt files with keys from an Entrust HSM.",
            prog="aes-encrypt.py",
            usage="%(prog)s [--encrypt | --decrypt] --input-file [INPUT_FILE] --output-file [OUTPUT_FILE] --token [TOKEN_LABEL] --key-label [KEY_LABEL]",
            epilog="Example: %(prog)s' --encrypt --input-file /home/administrator/encrypt_me.txt --output-file /home/administrator/decrypted.txt --token 'loadshared accelerator' --key-label my_key'\n",           
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=True,
            allow_abbrev=True,)
    parser.add_argument('-e', '--encrypt',
                        action='store_true',
                        help='Encrypt the input file',
                        default=False)
    parser.add_argument('-d', '--decrypt',
                        action='store_true',
                        help='Decrypt the input file',
                        default=False)
    parser.add_argument('-i', '--input-file',
                        help='The input file',
                        #type=str,                       
                        nargs='?')                       
    parser.add_argument('-o', '--output-file',
                        help='The output file',
                        #type = str,
                        nargs='?',)
                         
                        #encoding='utf-8')                        
    parser.add_argument('-t', '--token',
                        help='The token label',
                        action='store',
                        required=False)
    parser.add_argument('-k', '--key-label',
                        help='The key label',
                        action='store',
                        required=False)
    parser.add_argument('-p', '--pin',
                        help='The token pin',
                        required=False)
                         
                    
                   
 
# Parse the arguments
    args = vars(parser.parse_args())
    return args
 
# Define the main function 
def main():
    args = parse_args()
    encrypt_arg = args["encrypt"]
    decrypt_arg = args["decrypt"]
    pin = args["pin"]
    token_label = args["token"]
    key_label = args["key_label"]
    input_file_path = args["input_file"]
    output_file_path = args["output_file"]     
    
         
# Define main operations.
    if encrypt_arg and decrypt_arg:
        print("Please specify either encrypt or decrypt, not both.")
    elif encrypt_arg:
        encrypt(token_label, key_label,input_file_path, output_file_path, pin)
    elif decrypt_arg:
        decrypt(token_label, key_label, input_file_path, output_file_path, pin)
    else:
        print("Please specify either encrypt or decrypt.")
 
 
# Define the encrypt and decrypt functions.
 
def encrypt(token_label, key_label, input_file_path, output_file_path, pin):
    # Open a session
    token = lib.get_token(token_label=token_label)
    with token.open(rw=True ,user_pin=pin) as session:
        try:
            key = session.get_key(label=key_label)
        except pkcs11.NoSuchKey:
            print("No key found")
        except pkcs11.MultipleObjectsReturned:
            print("Multiple keys found")
         
        # Generate random IV and encrypt the file contents
        iv = session.generate_random(128)
        with open(input_file_path, 'rb') as file:
            data = file.read()
        ciphertext = key.encrypt(data, mechanism_param=iv)
             
        with open(output_file_path, "wb") as file:
            file.write(iv + ciphertext)
        print("File encrypted successfully")
         
def decrypt(token_label, key_label, input_file_path, output_file_path, pin):
     
    # Open a session
    token = lib.get_token(token_label=token_label)
    
    with token.open(rw=True ,user_pin=pin) as session:
        try:
           # Read the IV and decrypt the file contents
            with open(input_file_path, "rb") as file:
                iv = file.read(16)
                ciphertext = file.read()
            key = session.get_key(label=key_label)
 
            plaintext = key.decrypt(ciphertext, mechanism_param=iv)        
            
        except pkcs11.NoSuchKey:
            print("No key found")
        except pkcs11.MultipleObjectsReturned:
            print("Multiple keys found")
        except Exception as e:
            print(f"An error occurred during decryption: {e}")
        else:
            with open(output_file_path, "wb") as file:
                file.write(plaintext)
            print("File decrypted successfully")       
        
                  
         
 
# Call main.
                 
if __name__ == "__main__":
    main()
