# Entrust Python PKCS#11 Key Manager
# Author: Armando Montero
# Date: 2024/03/01
# Version: 1.0

# Import modules. 
import sys
import pkcs11
import argparse
import logging
import os
import datetime
from asn1crypto import pem
from rich import print
from rich.table import Table
from rich.console import Console
from rich import box
from pkcs11 import ObjectClass, lib, TokenNotPresent, NoSuchKey, KeyType, Attribute
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key
from pkcs11.util.dsa import encode_dsa_domain_parameters, decode_dsa_domain_parameters, encode_dsa_public_key, encode_dsa_signature, decode_dsa_public_key, decode_dsa_signature
  
# Setup Configuration
logging.basicConfig(level=logging.INFO)  # Config needed to default output to standard output
logger = logging.getLogger(__name__)
  
# Define the PKCS#11 DLL path
 
LIB = os.path.join(os.environ.get("NFAST_HOME", '/opt/nfast'),
                                  'toolkits', 'pkcs11', 'libcknfast.so')
lib = pkcs11.lib(LIB)
     
 
# Define environment variables.
os.environ["CKNFAST_LOADSHARING"] = "1"
os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = "unwrap_mech;tokenkeys"
os.environ["CKNFAST_FAKE_ACCELERATOR_LOGIN"] = "1"
 
 
# Custom class to allow attribute parsing.
 
class StoreAttributeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values is not None:
            for value in values:
                attr, bool_value = value.split('=')
                bool_value = bool_value.lower() in ['yes', 'true', 't', 'y', '1']
                setattr(namespace, self.dest, getattr(namespace, self.dest, []) + [(attr, bool_value)])
         
# Define arguments.
def parse_args():
    """
    Parse command line arguments for the PKCS#11 Key Manager.
 
    Returns:
        dict: A dictionary containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description="Entrust Python PKCS#11 Key Manager.\n\n"
                                                 "Version 1.0 (2024/02/01)\n\n"
                                                 "Written by: Armando Montero division of nShield & nCipher Support (DPS)\n\n",
                                     prog="keymanager.py",
                                     usage="%(prog)s [--generate] --algorithm RSA --key-size 4096 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--generate] --algorithm AES --key-size 256 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--generate] --algorithm EC --curve-name secp256r1 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--wrap] --algorithm AES --mechanism AES_KEY_WRAP --token 'loadshared accelerator' --label wrapping_key --key-to-wrap key_to_wrap --output-path /home/wrapped_key\n"
                                           "%(prog)s [--unwrap] --algorithm AES --mechanism AES_KEY_WRAP --token 'loadshared accelerator' --label wrapping_key --new-label unwrapped_key --file-path /home/wrapped_key\n"
                                           "%(prog)s [--sign] --algorithm RSA --token 'loadshared accelerator' --label key_label --file-path /home/data_to_sign --signature-path /home/signature\n"
                                           "%(prog)s [--verify] --algorithm RSA --token 'loadshared accelerator' --label key_label --file-path /home/data_to_verify --signature-path /home/signature\n"
                                           "%(prog)s [--encrypt] --algorithm AES --mechanism AES_CBC_PAD --token 'loadshared accelerator' --label key_label --file-path /home/data_to_encrypt --output-path /home/encrypted_data\n"
                                           "%(prog)s [--decrypt] --algorithm AES --mechanism AES_CBC_PAD --token 'loadshared accelerator' --label key_label --encrypted-path /home/encrypted_data --output-path /home/decrypted_data\n"
                                           "%(prog)s [--export] --algorithm RSA --token 'loadshared accelerator' --label key_label --output-path /home/exported_key\n"
                                           "%(prog)s [--delete] --algorithm AES --label AES_key_label --token 'loadshared accelerator '\n"
                                           "%(prog)s [--copy] --label default_key_label --new-label copied_key\n"
                                           "%(prog)s [--find-token] --token-label 'loadshared accelerator'\n"
                                           "%(prog)s [--list-slots]\n",
                                     allow_abbrev=True,
                                     add_help=True,
                                     epilog = " Supports AES, RSA, EC, 3DES, and DSA key generation, deletion, and copying. Provides functionality to perform secure cryptographic operations such as encryption, decryption, signing, verifying, wrapping, unwrapping, and export of public keys. Plan to add support for other algorithms and functions in the future.")
 
    parser.add_argument("-g", "--generate",
                        help="generate new keys",
                        required=False,
                        default=False,                       
                        action="store_true")
    parser.add_argument("-s", "--sign",
                        help="Sign data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-v", "--verify",
                        help="Verify data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-enc", "--encrypt",
                        help="Encrypt data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-dec", "--decrypt",
                        help="Decrypt data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-wra", "--wrap",
                        help="Wrap data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-unw", "--unwrap",
                        help="Unwrap data with the given with the given key label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument('-cp', '--copy',
                        help="Copy the key with the given label",
                        required=False,
                        action='store_true',
                        default=False,)
    parser.add_argument("-d", "--delete",
                        help="Delete the keys with the given version",
                        required=False,                        
                        action="store_true")  
    parser.add_argument("-e", "--export",
                        help="Export the key with the given label",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-fp", "--file-path",
                        help="The file path for the data to sign or encrypt",
                        required=False,
                        default=False)
    parser.add_argument("-op", "--output-path", 
                        help="The path for the signed or encrypted file",
                        required=False,
                        default=False)
    parser.add_argument("-sp", "--signature-path",
                        help="The path to store the signature to later compare with. If not provided, the signature will be printed to the console.",
                        required=False,
                        default=False) 
    parser.add_argument("-ep", "--encrypted-path",
                        help="The path for the encrypted file.",
                        required=False,
                        default=False)                  
    parser.add_argument("-p", "--pin",
                        help="The pin of the token to use",
                        required=False,
                        default="1234")  # Default pin if none is provided
    parser.add_argument("-t", "--token-label",
                        help="token label to use",
                        required=False,
                        default="loadshared accelerator")
    parser.add_argument("-l", "--label",
                        help="plaintext label name for the key",
                        required=False)
    parser.add_argument('-n', '--new-label',
                        help="The new label for the copied key",
                        required=False,
                        default='copied_key')
    parser.add_argument("-ktw", "--key-to-wrap",
                        help="The key to wrap",
                        required=False,
                        default=False)
    parser.add_argument("-k", "--key-size",
                        help="size of the key in bits",
                        required=False,
                        type=int,
                        choices=[128, 192, 256, 2048, 4096], 
                        default=False)  
    parser.add_argument('-c', '--curve-name',
                        help="The curve name for the key",
                        required=False,
                        type=str,
                        choices=['secp256r1','secp384r1','secp521r1','secp256k1','brainpoolP256r1','brainpoolP384r1','brainpoolP512r1'], 
                        default=False) 
    parser.add_argument('-prime', '--prime',
                        help="The prime number for the key",
                        required=False,
                        choices =[1024,2048],
                        default=False)
    parser.add_argument("-f", "--find-token",
                        help="find the token with the given label",
                        required=False,
                        action="store_true",
                        default=False)
    parser.add_argument("-lt", "--list-slots",
                        help="find the slot with the given label",
                        required=False,
                        action="store_true",
                        default=False)
    parser.add_argument("-ls", "--list-keys",
                        help="List all keys",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-attr", "--attribute",
                        help="Attribute to apply to the key",
                        required=False,
                        default=[],
                        nargs='+',
                        action=StoreAttributeAction)
    parser.add_argument("-alg", "--algorithm",
                        help="The algorithm to use for the key",
                        required=False,
                        type=str,
                        choices={"AES", "RSA", "EC", "SHA256", "SHA512", "SHA1", "SHA3", "MD5", "HMAC", "DES",
                                 "3DES", "X25519", "X448", "ED25519", "ECDH", "ECMQV", "ECIES", "ECDSA", "RSA", "DSA",
                                 "DH"},
                        default="AES")
    parser.add_argument('-m', '--mechanism',
                        help= "The mechanism to use for the operation, if not provided, a default mechanism will be used based on the algorithm",
                        choices = {"AES_KEY_WRAP_PAD", "AES_KEY_WRAP","AES_CBC_PAD", 
                                   "AES_CBC_ENCRYPT_DATA", "AES_ECB", "DES3_CBC_PAD", 
                                   "RSA_PKCS_OAEP","RSA_PKCS", "RSA_PKCS_OAEP_TPM_1_1", 
                                   "RSA_PKCS_TPM_1_1",},
                        required=False,
                        type=str,)
    parser.add_argument('-kt', '--key-type',
                        help="The key type specification for the key to unwrap",
                        required=False,
                        type=str,
                        choices={"SECRET", "PUBLIC_KEY", "PRIVATE_KEY"},
                        default=False)
 
 
    # Parse the arguments 
    args = vars(parser.parse_args())
    return args

 
# Main function
def main():
    
   #Args to store the parsed arguments
    args = parse_args()
    token_label = args["token_label"]   
    key_size = args["key_size"]   
    key_label = args["label"]
    new_label = args["new_label"]
    key_to_wrap = args["key_to_wrap"]
    pin = args["pin"]
    slot_label = args["list_slots"]    
    algorithm = args["algorithm"]
    curve = args["curve_name"]
    input_file_path = args["file_path"]
    output_file_path = args["output_path"]
    signature_path = args["signature_path"]
    encrypted_path = args["encrypted_path"]
    mechanism_type = args["mechanism"]
    key_type = args["key_type"]

     
# Call the appropriate function based on the arguments
    
    if args["generate"]:
        gen_key(args, token_label,key_label, key_size, aes_template, private_rsa_key_template, public_rsa_key_template, algorithm, curve, pin)      
    elif args["delete"]:
        delete_key(args,token_label,key_label,pin)   
    elif args["copy"]:
        key_copy(args,token_label,key_label,new_label, pin, algorithm)
    elif args["list_slots"]:
        get_slot(slot_label)    
    elif args["list_keys"]:
        list_keys(args,token_label)
    if args["find_token"]:
        find_token(args, token_label)
    elif args["sign"]:
        sign_data(args,token_label, key_label,input_file_path, signature_path, algorithm, pin)
    elif args["verify"]:
        verify_data(args,token_label,key_label,algorithm, input_file_path, signature_path)
    elif args["encrypt"]:
        encrypt_data(args,token_label,key_label,pin, algorithm, input_file_path, mechanism_type, output_file_path)
    elif args["decrypt"]:
        decrypt_data(args,token_label,key_label,encrypted_path,output_file_path, algorithm, mechanism_type, pin)
    elif args["wrap"]:
        wrap_data(args,token_label,key_label,key_to_wrap,algorithm,mechanism_type,output_file_path, pin)
    elif args["unwrap"]:
        unwrap_data(args,token_label, key_label, input_file_path, key_type, mechanism_type, algorithm, new_label, pin)
    elif args["export"]: 
       export_key(args, token_label, key_label, output_file_path, algorithm)
         
# Finds a specific token. 
def find_token(args,token_label):
    # Check for bad arguments
    if args["find_token"] and not args.get("token_label"):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the token label.")
        sys.exit(1)
    # Query the token.
    try:
        token = lib.get_token(token_label=token_label)
        
        # Create a console object
        console = Console() 
        
        # Create a table
        table = Table(show_header=True, header_style="red", show_lines=True, title="Token Found")
        table.title_style = "italic"
        table.border_style = "green"
        table.show_lines = True
        table.add_column("Token Label")
        table.add_column("Manufacturer ID")
        table.add_column("Model")
        table.add_column("Serial Number")
 
        # Add a row to the table for the token
        table.add_row(token.label, token.manufacturer_id, token.model, token.serial_number)
 
        # Print the table
        console.print(table)
         
    except pkcs11.TokenNotPresent:
        sys.exit(f"No token found with label='{token_label}'.")
    except pkcs11.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{token_label}'.")
 
# Find all keys within in all tokens. 
def list_keys(args,token_label):
    if args["generate"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "key_size"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, --token-label, --algorithm, and --pin.")
        sys.exit(1)
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True) as session:
           for public_keys in session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}):
               print_public_keys(token_label,public_keys)
           
           for private_keys in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}): 
               print_private_keys(token_label, private_keys)
                    
           for secret_keys in session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}):
               print_secret_keys(token_label, secret_keys)
            
                
    except pkcs11.exceptions.TokenNotPresent:
        sys.exit(f"No token found with label='{token_label}'.")
    except pkcs11.exceptions.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{token_label}'.")
                  
# Retrieve all slots information                  
def get_slot(slot_label):
    try:
        slots = lib.get_slots(token_present=True)
        
        # Format the slot list for printing
        slot_list = [str(s) for s in slots]   
        table = Table(show_header=True, header_style="gold1", show_lines=True, title="Slots information")
        table.add_column("Available Slots :smiley:", style="bright", width=45, justify="center")      
        table.title_style = "italic"
        table.title = "Slot information"
        table.border_style= "pale_turquoise4"
         
        for i, s in enumerate(slot_list, start=1):
            table.add_row(f"{i}. {s}")
             
    except pkcs11.exceptions.TokenNotPresent:
        sys.exit(f"No token found with label='{slot_label}'.")
    except pkcs11.exceptions.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{slot_label}'.")
        
    console = Console()
    console.print(table)
     
 
# Generate a key
 
def gen_key(args,token_label, key_label, key_size, aes_template, private_rsa_key_template, public_rsa_key_template, algorithm, curve, pin):
    
    # Check for bad arguments
    if args["generate"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "key_size"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, --token-label, --algorithm, and --pin.")
        sys.exit(1)
    
        
    # Generate the key based on the specified algorithm
    try:    
        token = lib.get_token(token_label=token_label)  
        with token.open(rw=True, user_pin=pin) as session:
             
            # Validate the specified algorithm
            if algorithm not in ALGORITHM_MAP:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
 
            algo_params = ALGORITHM_MAP[algorithm]
            key_type = algo_params["key_type"]
            curve = algo_params["default_size"]
 
            if key_size is None:
                key_size = algo_params["default_size"]
             
            if curve is None:
                curve = algo_params["default_size"]
             
            if algorithm == "AES":
                try:
                    # Find the key. If it does not exist, an exception will be raised
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")  
                    # Generate the key               
                key = session.generate_key(key_type, key_size, label=key_label, template=aes_template)
                print_aes_key_info(key)
        
            if algorithm == "RSA":
                try:
                    # Find the key. If it does not exist, an exception will be raised.
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")
                    # Generate the key.
                public, private = session.generate_keypair(key_type,key_length=modulus_bits,label=key_label,
                                                           public_template=public_rsa_key_template,
                                                           private_template=private_rsa_key_template,store=True)
                print_rsa_key_info(public, private)

 
            if algorithm == "EC":
                # For EC, we need to generate a public and private key pair and define the curve                            
                # See if key exists. 
                try:
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass 
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")                            
                # Create keypair. 
                    parameters = session.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(curve)}, local=True) # Requires local = True to create_domain_parameters                                       
                    public_key, private_key = parameters.generate_keypair(label=key_label, private_template= private_EC_template, public_template = public_EC_template, store=True)                    
                    print_ec_info(public_key, private_key)

            if algorithm == "DSA":
                try:
                    # See if key exists.                     
                    key = session.get_key(label= key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.exceptions.NoSuchKey:
                    pass
                except pkcs11.exceptions.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")
 
                # For DSA, we need to generate a public and private key pair
                # Generating the domain parameters and keypair                                          
                parameters = session.generate_domain_parameters(pkcs11.KeyType.DSA, 1024)
                public_DSA, private_DSA = parameters.generate_keypair(label=key_label, store=True)
 
                print_dsa_key_info(public_DSA, private_DSA)
                
    except pkcs11.FunctionFailed:
        sys.exit("Function failed")
    except pkcs11.PinInvalid:
        sys.exit("Pin invalid")
    except pkcs11.TemplateIncomplete:
        sys.exit("Template incomplete")
    except pkcs11.TemplateInconsistent:
        sys.exit("Template inconsistent")
    except pkcs11.TokenNotPresent:
        sys.exit("Token not present")
    except pkcs11.ArgumentsBad:
        sys.exit("Arguments bad")
    except pkcs11.AttributeValueInvalid:
        sys.exit("Attribute value invalid")
    except pkcs11.NoSuchToken:
        sys.exit("No such token")
          
    finally:
       lib.reinitialize()

# Copy a key 
def key_copy(args,token_label,key_label,new_label,pin,algorithm):
    
    # Check for bad arguments.
    if args["copy"] and not all(args.get(arg) for arg in ["label", "new_label", "token_label"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, --new-label, --token-label.")
        sys.exit(1)
    try:
        token = lib.get_token(token_label=token_label)
        # Open the token session.
        with token.open(rw=True, user_pin=pin) as session:
            # Verify if key_label exists
            try:
            # Copy based in algorithm type
               if algorithm in ["AES", "3DES"]:
                # Find the key. If it does not exist, an exception will be raised.
                existing_key = session.get_key(label=key_label)
            except pkcs11.NoSuchKey:
                sys.exit(f"No key found with label='{key_label}'.")
            try:    
                if algorithm in ["RSA", "EC", "DSA"]:
                    pub = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
                    priv = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
            except pkcs11.NoSuchKey:
                sys.exit(f"Public/Private key with label '{key_label}' does not exist.")
                
            # Verify if new_label does not exist
            try:
            
                if algorithm in ["AES", "3DES"]:       
                    session.get_key(label=new_label) 
                elif algorithm in ["RSA", "EC", "DSA"]:
                    session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=new_label)
                    session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=new_label)    
                sys.exit(f"Key with label '{new_label}' already exists.")
            except pkcs11.NoSuchKey:
                pass  # This is the expected case

            # Handle key copying based on the algorithm
            if algorithm in ["AES", "3DES"]:
                new_key = existing_key.copy({pkcs11.Attribute.LABEL: new_label})
                print_key_copy_success(token_label, key_label, new_label)
                
            elif algorithm in ["RSA", "EC", "DSA"]:
                try:
                    new_pub = pub.copy({pkcs11.Attribute.LABEL: new_label})
                    new_priv = priv.copy({pkcs11.Attribute.LABEL: new_label})
                    print_key_copy_success(token_label, key_label, new_label)
                except Exception as e:
                    sys.exit(f"An error occurred while copying the key: {e}")
            else:
                sys.exit(f"Unsupported algorithm '{algorithm}' for key copy.")
    except Exception as e:
        sys.exit(f"An error occurred during the operation. See logs for more information. {e}")
      
    
# Delete a key
 
def delete_key(args,token_label, key_label, pin):
    # Check for bad arguments
    if args["delete"] and not all(args.get(arg) for arg in ["label", "token_label"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the [green] --label, --token-label, and/or --pin.")
        sys.exit(1)
    try:
        # Define the token.
        token = lib.get_token(token_label=token_label)
        # Open a session and the delete the key.
        with token.open(rw=True, user_pin=pin) as session:
            key = session.get_key(label=key_label)
            key.destroy() 
            console = Console()
            table = Table(show_header=True, header_style="green", show_lines=True, title=":thumbs_up: Key Deleted:  ", box = box.ROUNDED, title_style="Bold", border_style="green", style="bright", width=80)
            table.add_column("Token Label")
            table.add_column("Deleted Key Label")
            table.add_row(token.label, key_label)
            console.print(table)
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")
    except pkcs11.MultipleObjectsReturned:
        sys.exit(f"Multiple keys found with label='{key_label}'.")
    except Exception as e:
        sys.exit(f"An error occurred while deleting the key: {e}")


 # Sign data with a key.

def sign_data(args, token_label, key_label, input_file_path, signature_path, algorithm, pin):
    # Check for bad arguments
    if args["sign"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "file_path", "signature_path"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the [green]--label, --token-label, --algorithm, --file-path, --signature-path, and/or --pin values.")
        sys.exit(1)
    # Define the token and time stamp.     
    try:
        token = lib.get_token(token_label=token_label)
        timestamp = datetime.datetime.now().strftime(" (Date & Time Signed: %d-%m-%Y") 
        time = datetime.datetime.now().strftime(" / %H:%M:%S)")
        # The data to sign. 
        data = open(input_file_path, 'rb').read()
        # Open a session with the token and signs. 
        with token.open(rw=True, user_pin=pin) as session:
          if algorithm in ["AES", "3DES"]: 
            key = session.get_key(label=key_label)
            signature = key.sign(data)

          elif algorithm in ["RSA", "DSA", "ECDSA"]:
            private_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
            signature = private_key.sign(data) 
            
          # Writes the signature to a file.  
          with open(signature_path, 'wb') as sig_file:
            sig_file.write(signature)
            signed_data_confirmation(token, key_label, input_file_path, signature_path + timestamp + time)
     
     # Error handling.      
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")
    except pkcs11.MechanismInvalid:
        sys.exit(f"Invalid mechanism for algorithm '{algorithm}'.")
    except pkcs11.SessionHandleInvalid:
        sys.exit("Invalid session handle.")
    except pkcs11.TokenNotPresent:
        sys.exit(f"No token found with label='{token_label}'.")
    except pkcs11.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{token_label}'.")
    except pkcs11.SignMixin:
        sys.exit("Sign failed.")
    except FileNotFoundError:
        sys.exit("Data file not found.")
    

# Verify signed data with a key.
def verify_data(args,token_label, key_label, algorithm, input_file_path, signature_path):
    # Check for bad arguments
    if args["verify"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "file_path", "signature_path"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the [green]--label, --token-label, --algorithm, --file-path, --signature-path and/or --pin values.")
        sys.exit(1)
    try:
        # Load data and signature from files
        with open(input_file_path, 'rb') as data_file, open(signature_path, 'rb') as sig_file:
            data = data_file.read()
            signature = sig_file.read()

        # Access the token and find the public key.
        with lib.get_token(token_label=token_label).open() as session:
            if algorithm in ['RSA', 'ECDSA', 'DSA']:
                public_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
                # Verify the signature
                verification_result = public_key.verify(data, signature)
                               
                verification_confirmation_asymmetric(verification_result, public_key)
            
            if algorithm in ['AES', '3DES']:
                # Finds the key and verifies the signature.
                key = session.get_key(label=key_label)                
                verification_result = key.verify(data, signature)                
                verification_confirmation_symmetric(verification_result, key)                         
            else:
                logger.error(f"Unsupported algorithm: {algorithm}")    
                sys.exit(1)            
# Error handling
    except TokenNotPresent:
        sys.exit(f"No token found with label '{token_label}'.")
    except NoSuchKey:
        sys.exit(f"No key found with label '{key_label}'.")
    except FileNotFoundError:
        sys.exit("Data or signature file not found.")
    except pkcs11.SignatureInvalid:
        sys.exit("Signature invalid.")
    except pkcs11.SignatureLenRange:
        sys.exit("Signature length out of range.")    
    except pkcs11.MechanismInvalid:
        sys.exit("Invalid mechanism.")    
    except Exception as e:
        sys.exit(f"An error occurred during verification: {str(e)}")

    

ENCRYPT_DECRYPT_MECHANISM_MAP = {
    "AES_CBC_PAD": {"mechanism": pkcs11.Mechanism.AES_CBC_PAD},
    "AES_CBC_ENCRYPT_DATA": {"mechanism": pkcs11.Mechanism.AES_CBC_ENCRYPT_DATA},
    "DES3_CBC_PAD": {"mechanism": pkcs11.Mechanism.DES3_CBC_PAD},
    "RSA_PKCS_OAEP": {"mechanism": pkcs11.Mechanism.RSA_PKCS_OAEP},
    "RSA_PKCS": {"mechanism": pkcs11.Mechanism.RSA_PKCS},
    "RSA_PKCS_OAEP_TPM_1_1": {"mechanism": pkcs11.Mechanism.RSA_PKCS_OAEP_TPM_1_1},
    "RSA_PKCS_TPM_1_1": {   "mechanism": pkcs11.Mechanism.RSA_PKCS_TPM_1_1},
    
    # The algorithm names as keys, mapping to their default mechanisms
    "AES": {"default_mechanism": pkcs11.Mechanism.AES_CBC_PAD},
    "3DES": {"default_mechanism": pkcs11.Mechanism.DES3_CBC_PAD},
    "RSA": {"default_mechanism": pkcs11.Mechanism.RSA_PKCS_OAEP},
    
}

# Encrypt data with a key
def encrypt_data(args,token_label, key_label, pin, algorithm, input_file_path, mechanism_type, output_file_path):
    if args["encrypt"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "file_path", "output_path"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the [green]--label --token-label, --algorithm, --file-path, --output-path, and --mechanism [/green]. [bold red]If no mechanism is provided, a default mechanism will be used based on the algorithm.")
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin=pin) as session:
            # Direct mapping to default mechanism if none provided
            if mechanism_type is None:
                if algorithm not in ENCRYPT_DECRYPT_MECHANISM_MAP:
                    raise ValueError(f"Unsupported algorithm: {algorithm}")
                mechanism_info = ENCRYPT_DECRYPT_MECHANISM_MAP[algorithm]
                mechanism = mechanism_info["default_mechanism"]
            else:
                # Validate and use the provided mechanism
                mechanism_key = mechanism_type
                if mechanism_key not in WRAP_MECHANISM_MAP:
                    raise ValueError(f"Invalid mechanism: {mechanism_type}")
                    sys.exit(1)
                mechanism = WRAP_MECHANISM_MAP[mechanism_key]["mechanism"]
            
            # Perform encryption
            if algorithm in ["AES", "3DES"]:
                # Symmetric encryption
                iv = session.generate_random(128)  # Adjust the IV size as needed
                key = session.get_key(label=key_label)
                
                
                with open(input_file_path, "rb") as input_file, open(output_file_path, "wb") as output_file:
                    data = input_file.read()
                    encrypted_data = key.encrypt(data, mechanism=mechanism, mechanism_param=iv)
                    output_file.write(iv + encrypted_data) # The IV is appended to the encrypted data, it is safe to store the IV in cleartext and required for decryption.

            elif algorithm in ["RSA"]:
                # Asymmetric encryption
                key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
                
                with open(input_file_path, "rb") as input_file, open(output_file_path, "wb") as output_file:
                    data = input_file.read()
                    encrypted_data = key.encrypt(data, mechanism=mechanism)
                    output_file.write(encrypted_data) 

            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Confirm encryption
            encrypt_confirmation(token, input_file_path, output_file_path, key_label, mechanism)

    except pkcs11.NoSuchKey:
        sys.exit(f"Key not found with label '{key_label}'.")
    except pkcs11.NoSuchToken:
        sys.exit(f"Token not found"f'{token}.')
    except pkcs11.PinIncorrect:
        sys.exit("Incorrect PIN")
    except pkcs11.TokenNotPresent:
        sys.exit("Token not present")
    except pkcs11.FunctionFailed:
        sys.exit("Function failed")
    except FileNotFoundError:
        sys.exit("File not found")
    except pkcs11.MechanismInvalid:
        sys.exit(f"Invalid mechanism for algorithm '{algorithm}'.")
    except pkcs11.PKCS11Error:
        sys.exit("PKCS11 Error")


# Decrypt data with a key. 

def decrypt_data(args,token_label, key_label, encrypted_path, output_file_path, algorithm, mechanism_type, pin):
    # Check for bad arguments
    if args["decrypt"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "encrypted_path", "output_path"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the [green]--label --token-label, --algorithm, --encrypted-path, --output-path, and --mechanism [/green]. [bold red]If no mechanism is provided, a default mechanism will be used based on the algorithm.")
        sys.exit(1)
    # Find Token
    try: 
        token = lib.get_token(token_label=token_label)
        # Open a Session. 
        with token.open(rw=True, user_pin = pin) as session:
            # Check mechanism if none uses default mechanism based on algorithm. 
            if mechanism_type is None:
                if algorithm not in ENCRYPT_DECRYPT_MECHANISM_MAP:
                    raise ValueError(f"Unsupported algorithm: {algorithm}")
                mechanism_info = ENCRYPT_DECRYPT_MECHANISM_MAP[algorithm]
                mechanism = mechanism_info["default_mechanism"]
            else:
                # Validate and use the provided mechanism
                mechanism_key = mechanism_type
                if mechanism_key not in ENCRYPT_DECRYPT_MECHANISM_MAP:
                    raise ValueError(f"Invalid mechanism: {mechanism_type}")
                mechanism = ENCRYPT_DECRYPT_MECHANISM_MAP[mechanism_key]["mechanism"]
         
            if algorithm in ["AES", "3DES"]:    
                with open(encrypted_path, "rb") as encrypted_file: 
                    # Read the IV from the file.            
                    iv = encrypted_file.read(16)
                    # Read the file and prep it for decryption. 
                    ciphertext = encrypted_file.read()                  
                                        
                    # Find the key to decrypt with.
                    key = session.get_key(label=key_label)
                    # Decrypt data using key. 
                    plaintext = key.decrypt(ciphertext, mechanism=mechanism, mechanism_param=iv, buffer_size=8192)
                    # Write decrypted data to file.
                with open(output_file_path, "wb") as decrypted_file:
                    decrypted_file.write(plaintext)
                    decrypt_confirmation(token, key_label, encrypted_path, output_file_path)
                        
            elif algorithm in ["RSA"]:
                # Find key
                key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
                # Open encrypted file and read it.
                with open(encrypted_path, "rb") as encrypted_file:
                    
                    ciphertext = encrypted_file.read()  
                    # Decrypt data using key.                  
                    plaintext = key.decrypt(ciphertext)
                # Write data to file.
                with open(output_file_path, "wb") as decrypted_file:
                    decrypted_file.write(plaintext)
                    decrypt_confirmation(token, key_label, encrypted_path, output_file_path)
                        
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")
    except pkcs11.FunctionFailed:
        sys.exit("Function failed")
    except pkcs11.AttributeTypeInvalid:
        sys.exit("Attribute type invalid")
    except pkcs11.DeviceRemoved:
        sys.exit("Token removed, please reload or insert token")
    except pkcs11.PinIncorrect:
        sys.exit("Incorrect PIN")
    except pkcs11.TokenNotPresent:
        sys.exit("Token not present")
    except pkcs11.NoSuchToken:
        sys.exit(f"No such token with label {token}")
    except FileNotFoundError:
        sys.exit("File not found")
    except Exception as e:
        sys.exit(f"An error occurred while decrypting the file: {e}")
        
WRAP_MECHANISM_MAP= {
    "AES_KEY_WRAP": {"mechanism": pkcs11.Mechanism.AES_KEY_WRAP},
    "AES_KEY_WRAP_PAD": {"mechanism": pkcs11.Mechanism.AES_KEY_WRAP_PAD},
    "AES_ECB": {"mechanism": pkcs11.Mechanism.AES_ECB},
    "RSA_PKCS_OAEP": {"mechanism": pkcs11.Mechanism.RSA_PKCS_OAEP},
    "DES3_CBC_PAD": {"mechanism": pkcs11.Mechanism.DES3_CBC_PAD},
    
    "AES": {"default_mechanism": pkcs11.Mechanism.AES_KEY_WRAP},
    "RSA": {"default_mechanism": pkcs11.Mechanism.RSA_PKCS_OAEP},
    "DES3": {"default_mechanism": pkcs11.Mechanism.DES3_CBC_PAD},                                   
 }

# Securely wrap keys with a wrapping key

def wrap_data(args,token_label, key_label, key_to_wrap, algorithm, mechanism_type,output_file_path, pin):
    # Check for bad arguments
    if args["wrap"] and not all(args.get(arg) for arg in ["label", "token_label", "key_to_wrap", "algorithm", "mechanism", "output_path", "pin"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, --token label, --key to wrap, --algorithm, --mechanism, --output-path, and/or --pin.If no mechanism is provided, a default mechanism will be used based on the algorithm.")
        sys.exit(1)  
    try:  
        # Define the token to use.
        token = lib.get_token(token_label = token_label)
        # Open a session. 
        with token.open(rw=True, user_pin=pin) as session:
            # Checks algorithm and mechanism type.
            if mechanism_type is None:
                if algorithm not in WRAP_MECHANISM_MAP:
                    raise ValueError(f"Unsupported algorithm: {algorithm}")
                mechanism_info = WRAP_MECHANISM_MAP[algorithm]
                mechanism = mechanism_info["default_mechanism"]
            else:
                # Validate and use the provided mechanism for the wrapping operation. 
                mechanism_key = mechanism_type
                if mechanism_key not in ENCRYPT_DECRYPT_MECHANISM_MAP:
                    raise ValueError(f"Invalid mechanism: {mechanism_type}")
                mechanism = ENCRYPT_DECRYPT_MECHANISM_MAP[mechanism_key]["mechanism"]
                
                # Wrap based on algorithm type.
            if algorithm in ["AES", "3DES"]: # 3DES IS CONSIDERED INSECURE USE AES WHERE POSSIBLE
                wrapping_key = session.get_key(label=key_label)
                wrapped_key = session.get_key(label=key_to_wrap)
                crypttext = wrapping_key.wrap_key(wrapped_key, mechanism =mechanism ,mechanism_param=None)  
                # Write the file. 
                with open(output_file_path, "wb") as wrapped_file:
                 wrapped_file.write(crypttext)
                 wrap_confirmation(token, key_label, key_to_wrap, output_file_path)
            
            if algorithm in ["RSA"]:
                wrapping_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
                wrapped_key = session.get_key(label=key_to_wrap)
                crypttext = wrapping_key.wrap_key(wrapped_key, mechanism=mechanism, mechanism_param=None) 
                # Write the file. 
                with open(output_file_path, "wb") as wrapped_file:
                 wrapped_file.write(crypttext)
                 wrap_confirmation(token, key_label, key_to_wrap, output_file_path)
        
        # Error Handling.        
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")
    except pkcs11.exceptions.FunctionFailed:
        sys.exit("Wrapping function failed")
    except pkcs11.exceptions.KeyHandleInvalid:
        sys.exit("Key handle invalid, you may be trying to wrap a key with WRAP_WITH_TRUSTED using an untrusted key")
    except pkcs11.exceptions.KeyNotWrappable:
        sys.exit("Key not wrappable")
    except pkcs11.exceptions.KeyUnextractable:
        sys.exit("Key unextractable")
    except pkcs11.exceptions.DeviceRemoved:
        sys.exit("Token removed, please reload or insert token")
    except pkcs11.exceptions.PinIncorrect:
        sys.exit("Incorrect PIN")
    except pkcs11.exceptions.TokenNotPresent:
        sys.exit("Token not present")
    except FileNotFoundError:
        sys.exit("File not found")

# Securely unwrap keys onto Hardware Security Module (HSM) with the wrapping key for secure key storage.

def unwrap_data(args, token_label, key_label, input_file_path, key_type, mechanism_type, algorithm, new_label, pin): 
    # Check bad arguments.
    if args["unwrap"] and not all(args.get(arg) for arg in ["label", "token_label", "algorithm", "file_path", "key_type", "mechanism", "new_label"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, --token-label, --algorithm, --file-path, --key-type, --mechanism, --new-label, and/or --pin.") 
    try:
        # Define the token. 
        token = lib.get_token(token_label = token_label)
        # Open a session. 
        with token.open(rw=True, user_pin=pin) as session:
            # Open the wrapped key material. 
            with open(input_file_path, "rb") as wrapped_file:
                # Checks algorithm and mechanism type.
                if mechanism_type is None:
                    if algorithm not in WRAP_MECHANISM_MAP:
                        raise ValueError(f"Unsupported algorithm: {algorithm}")
                    mechanism_info = WRAP_MECHANISM_MAP[algorithm]
                    mechanism = mechanism_info["default_mechanism"]
                else:
                    # Validate and use the provided mechanism
                    mechanism_key = mechanism_type
                    if mechanism_key not in ENCRYPT_DECRYPT_MECHANISM_MAP:
                        raise ValueError(f"Invalid mechanism: {mechanism_type}")
                    mechanism = ENCRYPT_DECRYPT_MECHANISM_MAP[mechanism_key]["mechanism"]
                    
                # Read the wrapped key material.
                crypttext = wrapped_file.read()
                # Unwrap based on algorithm type.
                if algorithm == "AES":
                    wrapping_key = session.get_key(label=key_label)
                    unwrapped_key = wrapping_key.unwrap_key(object_class = ObjectClass.SECRET_KEY, key_type = KeyType.AES, mechanism= mechanism, 
                                                        mechanism_param=None, 
                                                        key_data = crypttext,
                                                        label=new_label, 
                                                        store=True,
                                                        template= {Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False, Attribute.WRAP_WITH_TRUSTED: True, 
                                                                   Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.WRAP: True, Attribute.UNWRAP: True, Attribute.SIGN: True, Attribute.VERIFY: True}) # Can be modified or template = None for default values.
                    
                    unwrap_confirmation(token, key_label, input_file_path, unwrapped_key)
                
                if algorithm =="RSA":
                    wrapping_key = session.get_key(label=key_label, object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY)
                    
                    unwrapped_key = wrapping_key.unwrap(ObjectClass.PRIVATE_KEY, key_type, crypttext, mechanism=mechanism, mechanism_param=None, label=new_label, store=True)
                    unwrap_confirmation(token, key_label, input_file_path, unwrapped_key)
                
    # Error Handling.
    except pkcs11.NoSuchKey:
        sys.exit(f"No wrapping key found with label'{key_label}'.")
    except pkcs11.FunctionFailed:
        sys.exit("Function failed")
    except pkcs11.TemplateInconsistent:
        sys.exit("Template inconsistent")
    except pkcs11.UnwrappingKeyHandleInvalid:
        sys.exit("Unwrapping key handle invalid")
    except pkcs11.UnwrappingKeySizeRange:
        sys.exit("Unwrapping key size range")
    except pkcs11.DeviceRemoved:
        sys.exit("Token removed, please reload or insert token")
    except pkcs11.exceptions.PinIncorrect:
        sys.exit("Incorrect PIN")
    except pkcs11.exceptions.TokenNotPresent:
        sys.exit("Token not present") 

# Export keys from the HSM      
# Only configured to export the public key. Private & Secret keys should remain within the HSM boundary.    
    
def export_key(args,token_label, key_label, output_file_path, algorithm): 
    # Check for bad arugments
    if args["export"] and not all(args.get(arg) for arg in ["label", "token_label", "output_path", "algorithm"]):
        print("[bold red]Error:[/bold red] Missing required arguments. Please specify the label, token label, output path, and algorithm.")
        sys.exit(1)
    
    try:    
        # Define the token.
        token = lib.get_token(token_label=token_label)
        # Open a session.
        with token.open(rw=True) as session:
           # Access the token and find the key.
            key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
            if algorithm == "RSA":
                    exported_key = pkcs11.util.rsa.encode_rsa_public_key(key)
            if algorithm == "DSA":
                    exported_key = pkcs11.util.dsa.encode_dsa_public_key(key)
            if algorithm == "EC":
                    exported_key = pkcs11.util.ec.encode_ec_public_key(key)
        
        # Write the public key to the specified output file 
        with open(output_file_path, "wb") as key_file:
            # Write the public key attributes to the specified output file
            if output_file_path.endswith('.pem'):
                pem_output = output_file_path
                der_output = output_file_path[:-4] + '.der'
            elif output_file_path.endswith('.der'):
                pem_output = output_file_path[:-4] + '.pem'
                der_output = output_file_path
            else:
                pem_output = output_file_path + '.pem'
                der_output = output_file_path + '.der'
                    
            # Write the public key to the specified output file in DER format
            with open(der_output, 'wb') as der_file:
                 der_file.write(exported_key)
            # Write the public key to the specified output file in PEM format
            with open(pem_output, 'wb') as pem_file:
                pem_file.write(pem.armor('PUBLIC KEY', exported_key))
            exported_key_confirmation(token, key_label, output_file_path)

                
    # Error Handling
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")
    except pkcs11.KeyUnextractable:
        sys.exit("Key unextractable, key must be extractable to export")
    except pkcs11.FunctionFailed:
        sys.exit("Function failed")
    except pkcs11.AttributeSensitive:
        sys.exit("Attribute sensitive, key must be not sensitive to export")  
    except pkcs11.DeviceRemoved:
        sys.exit("Token removed, please reload or insert token")
    except pkcs11.PinIncorrect:
        sys.exit("Incorrect PIN")
    except pkcs11.TokenNotPresent:# Only configured to export the public key. Private & Secret keys should remain within the HSM boundary.
        sys.exit("Token not present")      
        

####################### TEMPLATE SECTION ############################
 
# AES Key Template
aes_template = {pkcs11.Attribute.TOKEN: "TOKEN",
            pkcs11.Attribute.SENSITIVE: "SENSITIVE",
            pkcs11.Attribute.EXTRACTABLE: "EXTRACTABLE",
            pkcs11.Attribute.WRAP_WITH_TRUSTED: "WRAP_WITH_TRUSTED",
            pkcs11.Attribute.ENCRYPT: "ENCRYPT",
            pkcs11.Attribute.DECRYPT: "DECRYPT",
            pkcs11.Attribute.WRAP: "WRAP",
            pkcs11.Attribute.UNWRAP: "UNWRAP",
            pkcs11.Attribute.SIGN: "SIGN",
            pkcs11.Attribute.VERIFY: "VERIFY",  
            }
 
# RSA Key Template
 
args = parse_args()
rsa_key_length = args["key_size"]
modulus_bits = rsa_key_length
 
public_rsa_key_template = {pkcs11.Attribute.TOKEN: "TOKEN",            
            pkcs11.Attribute.MODULUS_BITS: modulus_bits,            
            pkcs11.Attribute.ENCRYPT: "ENCRYPT",           
            pkcs11.Attribute.WRAP: "WRAP",           
            pkcs11.Attribute.VERIFY: "VERIFY"}
 
private_rsa_key_template = {pkcs11.Attribute.TOKEN: "TOKEN",
            pkcs11.Attribute.SENSITIVE: "SENSITIVE",            
            pkcs11.Attribute.MODULUS_BITS: modulus_bits,            
            pkcs11.Attribute.DECRYPT: "DECRYPT",          
            pkcs11.Attribute.UNWRAP: "UNWRAP",
            pkcs11.Attribute.SIGN: "SIGN"}

# EC Template

private_EC_template= {pkcs11.Attribute.TOKEN: True,                     
                      pkcs11.Attribute.PRIVATE: True,                     
                      pkcs11.Attribute.SIGN: True,
                      pkcs11.Attribute.SIGN_RECOVER: False, 
                      }
public_EC_template = {pkcs11.Attribute.TOKEN: True,                    
                      pkcs11.Attribute.SIGN: False,                      
                      pkcs11.Attribute.VERIFY: True,
                      pkcs11.Attribute.VERIFY_RECOVER: False,
                      }
 
# Grab parse for attribute values.
args = parse_args()      
attribute_values = args["attribute"] 
 
# Iterate through the attribute values and apply them to the template
 
for attr, value in attribute_values:
    # Convert the attribute name to its corresponding attribute value
    attr = getattr(pkcs11.Attribute, attr)
 
    # Apply the boolean value to the template
    aes_template[attr] = value
    # Create a function to parse attribute values
    def parse_attributes(attribute_values, template):
        for attr, value in attribute_values:
            # Convert the attribute name to its corresponding attribute value
            attr = getattr(pkcs11.Attribute, attr)
 
            # Apply the attribute value to the template
            template[attr] = value
 
    # Parse attribute values for AES template
    parse_attributes(attribute_values, aes_template)
 
    # Parse attribute values for RSA templates
    parse_attributes(attribute_values, public_rsa_key_template)
    parse_attributes(attribute_values, private_rsa_key_template)

ALGORITHM_MAP = {
    "AES": {"key_type": pkcs11.KeyType.AES, "default_size": 256},
    "RSA": {"key_type": pkcs11.KeyType.RSA, "default_size": 4096},
    "EC": {"key_type": pkcs11.KeyType.EC, "default_size": 'secp256r1' },
    "DSA": {"key_type": pkcs11.KeyType.DSA, "default_size": 1024},
    
}        
                    
                                       
                                        ######## Printing Functions ##########
# For export_key function

def exported_key_confirmation(token, key_label, output_file_path):
    table = Table(show_header=True, header_style="green", show_lines=True, title=" Public Key Successfully Exported!", 
                  title_style="Bold", border_style="bright_black", style="bright", width=150, box= box.ROUNDED)
    table.add_column("Token Label")
    table.add_column("Exported Key Label")
    table.add_column("Exported Key Material File (DER)")
    table.add_column("Exported Key Material File (PEM)")
    table.add_row(token.label, key_label, output_file_path + '.der', output_file_path + '.pem')
            
    console = Console()
    console.print(table)                                       
                                        
# for import_key function
def imported_key_confirmation(token, key_label, input_file_path):
    table = Table(show_header=True, header_style="green", show_lines=True, title=":thumbs_up: Key Imported:  ", 
                  padding = 1,title_style="Bold", border_style="bright_black", style="bright", width=150, box= box.ROUNDED)
    table.add_column("Token Label")
    table.add_column("Imported Key Label")
    table.add_column("Key Material File")
    table.add_row(token.label, key_label, input_file_path)
            
    console = Console()
    console.print(table)                                        
                                        
# For sign_data function 

def signed_data_confirmation(token, key_label, input_file_path, signature_path):
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title=":smiley: File Signed!  ", title_style="Regular",
                     box = box.ROUNDED, border_style="green", style="bright", width=150)
    table.add_column("Token Label")
    table.add_column("Key Label")
    table.add_column("File to Sign")
    table.add_column("Signature File")
    table.add_row(token.label, key_label, input_file_path, signature_path)
    
    console = Console()
    console.print(table)
                          
                                        
# For wrap_data function
def wrap_confirmation(token, key_label, key_to_wrap, output_file_path):
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title=":smiley: Key Wrapped:  ", 
                  box = box.ROUNDED, title_style="Bold", border_style="bright_black", style="bright", width=150)
    table.add_column("Token Label")
    table.add_column("Wrapping Key Label")
    table.add_column("Key to Wrap")
    table.add_column("Wrapped Key Material File")
    table.add_row(token.label, key_label, key_to_wrap, output_file_path)
            
    console = Console()
    console.print(table)                                        
 
 
# For unwrap_data function
def unwrap_confirmation(token, key_label, input_file_path, unwrapped_key):
    table = Table(show_header=True, header_style="green,", box = box.ROUNDED,
                  show_lines=True, title=":thumbs_up: Key Unwrapped:  ", title_style="Bold", border_style="bright_black", style="bright", width=150)
    table.add_column("Token Label")
    table.add_column("Wrapping Key Label")
    table.add_column("Wrapped Key Material File")
    table.add_column("Unwrapped Key Label")
    table.add_row(token.label, key_label, input_file_path, unwrapped_key.label)
            
    console = Console()
    console.print(table) 
 # For encrypt_data function 
 
def encrypt_confirmation(token, input_file, output_file, key_label, mechanism):
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title=":thumbs_up: File Encrypted:  ", 
                  padding = 1,title_style="Bold", border_style="bright_black", style="bright", width=150, box= box.ROUNDED)
    table.add_column("Token Label")
    table.add_column("File to encrypt")
    table.add_column("Encrypted File")
    table.add_column("Key Label")
    table.add_column("Mechanism")
    table.add_row(token.label, str(input_file), str(output_file), key_label, mechanism.name)
            
    console = Console()
    console.print(table) 
            

def decrypt_confirmation(token, key_label, input_file_path, output_file_path):
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title=":thumbs_up: File Decrypted:  ",
                  title_style="Bold", border_style="bright_black", style="bright", width=150, box= box.ROUNDED)
    table.add_column("Token Label")
    table.add_column("File to decrypt")
    table.add_column("Decrypted File")
    table.add_column("Key Label")
    table.add_row(token.label, input_file_path, output_file_path, key_label) 
               
    console = Console()
    console.print(table)
            
 # For verify_data function using symmetric keys             
def verification_confirmation_symmetric(verification_result, key):
 table = Table(show_header=True, header_style="dark_green",
               box = box.ROUNDED, title="File Verified :thumbs_up:", style="Bold", border_style = "green", show_lines=True)
 table.add_column("Signature Verification Result")
 table.add_column("Signed by Secret Key Label") 
 table.add_row(str(verification_result), key.label)
 
 console = Console()
 console.print(table)              
 
 # For verify_data function using asymmetric keys
def verification_confirmation_asymmetric(verification_result, public_key):
    table = Table(show_header=True, header_style="dark_green",box = box.ROUNDED, 
                  border_style= "green", style="Bold", show_lines=True)
    table.add_column("Signature Verification Result")
    table.add_column("Signed by Public Key Label")    
    table.add_row(str(verification_result),public_key.label)
    
    console = Console()
    console.print(table)
                
# Print AES info ##

def print_aes_key_info(key):
# Create and define a table for the key information
  console = Console()
 
  table = Table(show_header=True, header_style="dark_green", show_lines=False, box = box.ROUNDED, title="Key Information")
  table.add_column("Attribute", style="bright", width=50, justify="center") 
  table.add_column("Value", style="bright", width=50, justify="center")
  table.title_style = "bold"
  table.border_style = "green"
     
  key_info = {
        "LABEL": key.__getitem__(pkcs11.Attribute.LABEL),
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
        "VERIFY": key.__getitem__(pkcs11.Attribute.VERIFY),
         
    }       
  # Extra formatting for key size and key type.     
  for attribute, value in key_info.items():    
    if attribute == "KEY SIZE":
        key_size = str(value) + " bits"
        if value == 32:
            key_size = "256 bits"
        elif value == 16:
            key_size = "128 bits"
        elif value == 25:
            key_size = "128 bits"
        table.add_row(attribute, key_size)
    if attribute == "KEY TYPE":
        key_type = str(value) 
        if value == KeyType.AES:
            key_type = "AES"
        if value == KeyType.DES3:
            key_type = "3DES"
        if value == KeyType.RSA:
            key_type = "RSA"
        if value == KeyType.EC:
            key_type = "EC"
        if value == KeyType.DSA:
            key_type = "DSA"
        table.add_row(attribute, key_type)
    else:
        table.add_row(attribute, str(value))
    table.title = "AES Key Generated Succesfully!"
    
  console.print(table)
 
 ## print RSA info ##
 
def print_rsa_key_info(public, private):
    
    # Create a table for the key information
    
    console = Console()
    table = Table(show_header=True, header_style="dark_green", show_lines=True, border_style= "green" ,title=" Key Pair Generated Succesfully!")
    table.add_column("Attribute", style="dim", width=25, justify="center")
    table.add_column("Value", style="bright", width=20, justify="center")
    table.title_style = "bold"
    table.border_style = "bright_black"
    
    
    public_info = {
        "LABEL": public.__getitem__(pkcs11.Attribute.LABEL),
        "TOKEN": public.__getitem__(pkcs11.Attribute.TOKEN),
        "KEY TYPE": public.__getitem__(pkcs11.Attribute.KEY_TYPE),
        "KEY SIZE": public.__getitem__(pkcs11.Attribute.MODULUS_BITS),
        "TRUSTED": public.__getitem__(pkcs11.Attribute.TRUSTED),
        "PRIVATE": public.__getitem__(pkcs11.Attribute.PRIVATE),
        "MODIFIABLE": public.__getitem__(pkcs11.Attribute.MODIFIABLE),
        "ENCRYPT": public.__getitem__(pkcs11.Attribute.ENCRYPT),
        "WRAP": public.__getitem__(pkcs11.Attribute.WRAP),
        "VERIFY": public.__getitem__(pkcs11.Attribute.VERIFY)}
   
        
    
    private_info = {"EXTRACTABLE": private.__getitem__(pkcs11.Attribute.EXTRACTABLE),
                    "WRAP WITH TRUSTED": private.__getitem__(pkcs11.Attribute.WRAP_WITH_TRUSTED),                    
                    "DECRYPT": private.__getitem__(pkcs11.Attribute.DECRYPT),                    
                    "UNWRAP": private.__getitem__(pkcs11.Attribute.UNWRAP),
                    "SIGN": private.__getitem__(pkcs11.Attribute.SIGN),
           
    }        
         
    for attribute, value in public_info.items():
           table.add_row(attribute, str(value))
           table.title = "Public Key Information"
    console.print(table)
    
    for attribute, value in private_info.items():
        table.title = "Private Key Information"
        table.add_row(attribute, str(value))
    console.print(table)
   
  
 # Print DSA Key Information
  
def print_dsa_key_info(public_DSA, private_DSA):
    # Create a table for the key information
    console = Console()
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title=" Key Pair Generated Successfully!")
    table.add_column("Attribute", style="dim", width=25, justify="center")
    table.add_column("Value", style="bright", width=20, justify="center")
    table.title_style = "bold"
    table.border_style = "green"
    
    
    public_info = {"LABEL": public_DSA.__getitem__(pkcs11.Attribute.LABEL),
        "TOKEN": public_DSA.__getitem__(pkcs11.Attribute.TOKEN),
        "KEY TYPE": public_DSA.__getitem__(pkcs11.Attribute.KEY_TYPE),
        "PRIME": public_DSA.__getitem__(pkcs11.Attribute.PRIME),   
        "SUBPRIME": public_DSA.__getitem__(pkcs11.Attribute.SUBPRIME),
        "BASE": public_DSA.__getitem__(pkcs11.Attribute.BASE),       
        "LOCAL": public_DSA.__getitem__(pkcs11.Attribute.LOCAL),}
        #"EXTRACTABLE": public_DSA.__getitem__(pkcs11.Attribute.EXTRACTABLE),
        #"SIGN": public_DSA.__getitem__(pkcs11.Attribute.SIGN),
        #"VERIFY": public_DSA.__getitem__(pkcs11.Attribute.VERIFY)}
        #"SENSITIVE": public_DSA.__getitem__(pkcs11.Attribute.SENSITIVE),}
         
     
     
    private_info = {"LABEL": private_DSA.__getitem__(pkcs11.Attribute.LABEL),}
       
  
    for attribute, value in public_info.items():
              table.add_row(attribute, str(value))
              table.width = 100
              table.title = "Public Key Information"
    console.print(table)
     
    for attribute, value in private_info.items():
        table.title = "Private Key Information"
        table.width = 100
        table.add_row(attribute, str(value))
    console.print(table)
    

# Print ECDSA Key Information

def print_ec_info(public, private):
     # Create a table for the key information
    console = Console()
    table = Table(show_header=True, header_style="dark_green", show_lines=True, title="Key Information")
    table.add_column("Attribute", style="dim", width=25, justify="center")
    table.add_column("Value", style="bright", width=20, justify="center")
    table.title_style = "italic"
    table.border_style = "bright black"
    

    public_info = {"LABEL": public.__getitem__(pkcs11.Attribute.LABEL),
        "TOKEN": public.__getitem__(pkcs11.Attribute.TOKEN),
        "KEY TYPE": public.__getitem__(pkcs11.Attribute.KEY_TYPE),
        "CURVE": public.__getitem__(pkcs11.Attribute.EC_PARAMS),
        "EC POINT": public.__getitem__(pkcs11.Attribute.EC_POINT),
        #"SIGN": public.__getitem__(pkcs11.Attribute.SIGN), #  Not allowed in public key
        #"VERIFY": public.__getitem__(pkcs11.Attribute.VERIFY), #  Not allowed in public key
    }
    
    private_info = { "LABEL": private.__getitem__(pkcs11.Attribute.LABEL),
                    "TOKEN": private.__getitem__(pkcs11.Attribute.TOKEN),
                    "KEY TYPE": private.__getitem__(pkcs11.Attribute.KEY_TYPE),
                    "CURVE": private.__getitem__(pkcs11.Attribute.EC_PARAMS),}
                    #"SIGN": private.__getitem__(pkcs11.Attribute.SIGN), #  Not allowed in private key


                
    for attribute, value in public_info.items():
     table.add_row(attribute, str(value))
     table.title = "Public Key Information"
    console.print(table)
    
    for attribute, value in private_info.items():
     table.title = "Private Key Information"
     table.add_row(attribute, str(value))
    console.print(table)
    
 # For key_copy function   
                
def print_key_copy_success(token_label, key_label, new_label):
    console = Console()
    table = Table(show_header=True, header_style="dark_green", box = box.ROUNDED, show_lines=True, title="Key Copied Successfully!", title_style="bold", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Copied Key Label")
    table.add_column("New Key Label")
    table.add_row(token_label, key_label, new_label)
    console.print(table)       
                    

# For list_keys function

def print_public_keys(token_label, public_keys):
    console = Console()
    table = Table(show_header=True, header_style="dark_green", box=box.ROUNDED, show_lines=True, title="Public Key Found:", title_style="bold", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")
    table.add_column("Key Type")
    
    

    if public_keys.key_type == KeyType.RSA:   
        table.add_column("Key Size")     
        modulus = str(public_keys[Attribute.MODULUS_BITS])
        table.add_row(token_label, public_keys.label, str(public_keys.key_type), str(modulus) + "bits")
    elif public_keys.key_type == KeyType.DSA:
        table.add_column("Prime")
        table.add_column("Subprime") 
        table.add_column("Base")
        table.add_row(token_label, public_keys.label, str(public_keys.key_type), str(public_keys[Attribute.PRIME].hex()), str(public_keys[Attribute.SUBPRIME].hex()), str(public_keys[Attribute.BASE].hex()))
    elif public_keys.key_type == KeyType.EC:
        table.add_column("Curve")
        curve = str(public_keys[Attribute.EC_PARAMS])
        table.add_row(token_label, public_keys.label, str(public_keys.key_type), str(curve))
    
    console.print(table)
           
def print_private_keys(token_label, private_keys):
    console = Console()
    table = Table(show_header=True, header_style="dark_green", box = box.ROUNDED, show_lines=True, title= "Private Key Found", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")
    table.add_column("Key Type")
    
    if private_keys.key_type == KeyType.RSA:
        table.add_column("Key Size")
        
        table.add_row(token_label, private_keys.label, str(private_keys.key_type), str(private_keys[Attribute.MODULUS_BITS]) +  "bits")
    if private_keys.key_type == KeyType.DSA:
        table.add_column("Prime")
        table.add_column("Subprime")
        table.add_column("Base")        
        table.add_row(token_label, private_keys.label, str(private_keys.key_type), str(private_keys[Attribute.PRIME].hex()), str(private_keys[Attribute.SUBPRIME].hex()), str(private_keys[Attribute.BASE].hex()))
    if private_keys.key_type == KeyType.EC:
        table.add_column("Curve")
        curve = str(private_keys[Attribute.EC_PARAMS])
        table.add_row(token_label, private_keys.label, str(private_keys.key_type),str(curve))
    console.print(table)   
                    
           
def print_secret_keys(token_label, secret_keys):
    console = Console()
    table = Table(show_header=True, header_style="dark_green", show_lines=True, box = box.ROUNDED, title= "Secret Key Found", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")    
    table.add_column("Key Type")
    table.add_column("Key Size")
    key_length = str(secret_keys.key_length)
    table.add_row(token_label, secret_keys.label, str(secret_keys.key_type), str(key_length) + "bits")
    console.print(table)

# Call to main function
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(repr(e))
        raise e

