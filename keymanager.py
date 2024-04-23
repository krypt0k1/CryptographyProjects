import sys
import pkcs11
import argparse
import logging
import os
from rich import print
from rich.table import Table
from rich.console import Console
from pkcs11 import Mechanism, ObjectClass, lib, TokenNotPresent, NoSuchKey, KeyType, Attribute, MGF
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key, decode_rsa_private_key
from pkcs11.util.dsa import encode_dsa_domain_parameters, decode_dsa_domain_parameters, encode_dsa_public_key, encode_dsa_signature, decode_dsa_public_key, decode_dsa_signature
import os
 
 
  
  
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
                                     prog="keygen.py",
                                     usage="%(prog)s [--generate] --algorithm RSA --key-size 4096 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--generate] --algorithm AES --key-size 256 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--generate] --algorithm DSA --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--generate] --algorithm EC --curve secp256r1 --token-label 'loadshared accelerator' --label new_key --pin 1234\n"
                                           "%(prog)s [--delete] --label key_label --token 'loadshared accelerator'\n"
                                           "%(prog)s [--copy] --label default_key_label --new-label copied_key\n"
                                           "%(prog)s [--find-token] --token-label 'loadshared accelerator'\n"
                                           "%(prog)s [--list-slots]\n"
                                           "%(prog)s [--find-token] --token-label 'loadshared accelerator'",
                                     allow_abbrev=True,
                                     add_help=True,
                                     epilog = " Supports AES, RSA, EC, 3DES, and DSA key generation, deletion, and copying. Plan to add support for other algorithms and functions in the future.")
 
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
                        default=False,
                        action="store_true")
    parser.add_argument("-i", "--import",
                        help="Import the key with the given label",
                        required=False,
                        default=False,
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
                        required=False,
                        default="default_key_label")  # Default label if none is provided
    parser.add_argument('-n', '--new-label',
                        help="The new label for the copied key",
                        required=False,
                        default='copied_key')
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
                       # required=False,
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
 
    
 
    args = vars(parser.parse_args())
    return args
   
       
     
 
# Main function
def main():
    args = parse_args()
    token_label = args["token_label"]   
    key_size = args["key_size"]   
    key_label = args["label"]
    new_label = args["new_label"]
    pin = args["pin"]
    slot_label = args["list_slots"]    
    algorithm = args["algorithm"]
    curve = args["curve_name"]
    input_file_path = args["file_path"]
    output_file_path = args["output_path"]
    signature_path = args["signature_path"]
    encrypted_path = args["encrypted_path"]
    
    
     
 
     
# Call the appropriate function based on the arguments
    if args["find_token"]:
        find_token(token_label)
    elif args["generate"]:
        gen_key(token_label, key_label, key_size, aes_template, private_rsa_key_template, public_rsa_key_template, algorithm, curve, pin)      
    elif args["delete"]:
        delete_key(token_label, key_label,pin)    
    elif args["list_slots"]:
        get_slot(slot_label)
    elif args["copy"]:
        key_copy(token_label, key_label, new_label, pin)
    elif args["list_keys"]:
        list_keys(token_label)
    elif args["sign"]:
        sign_data(token_label, key_label, input_file_path, signature_path, algorithm, pin)
    elif args["verify"]:
        verify_data(token_label, key_label, algorithm, input_file_path, signature_path)
    elif args["encrypt"]:
        encrypt_data(token_label, key_label, pin,  algorithm, input_file_path, output_file_path)
    elif args["decrypt"]:
        decrypt_data(token_label, key_label, encrypted_path, output_file_path, algorithm, pin)
    #elif args["wrap"]:
     #   wrap_data(token_label, key_label, file_path, pin) 
   # elif args["unwrap"]:
    #    unwrap_data(token_label, key_label, file_path, pin)
   # elif args["import"]:
    #    import_key(token_label, key_label, file_path, pin)
   # elif args["export"]:
   #    export_key(token_label, key_label, file_path, pin)
         
# Finds a specific token.
 
def find_token(token_label):
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
 
    except pkcs11.exceptions.TokenNotPresent:
        sys.exit(f"No token found with label='{token_label}'.")
    except pkcs11.exceptions.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{token_label}'.")
 
# Find all keys within in all tokens. 
def list_keys(token_label):
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
 
 
# Grab parse for attribute values.
args = parse_args()      
attribute_values = args["attribute"] 
 
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
    # Add more mappings as necessary
}
 
 
# Generate a key
 
def gen_key(token_label, key_label, key_size, aes_template, private_rsa_key_template, public_rsa_key_template, algorithm, curve, pin):
        
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
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")
                 
                key = session.generate_key(key_type, key_size, label=key_label, template=aes_template)
                print_aes_key_info(key)
 
            elif algorithm == "RSA":
                try:
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")
                 
                public, private = session.generate_keypair(
                    key_type,
                    key_length=modulus_bits,
                    label=key_label,
                    public_template=public_rsa_key_template,
                    private_template=private_rsa_key_template,
                )
                     
                print_rsa_key_info(public, private)
 
            elif algorithm == "EC":
                # For EC, we need to generate a public and private key pair and define the curve
                             
                # Code to generate EC key pair
                try:
                    key = session.get_key(label=key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.NoSuchKey:
                    pass
                except pkcs11.MultipleObjectsReturned:
                    sys.exit(f"Multiple keys found with label='{key_label}'.")
                 
                 
                parameters = session.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(curve)}, local=True) # Requires local = True to create_domain_parameters
                 
                
                public_key, private_key = parameters.generate_keypair(label=key_label, store=True)
                 
                print_ec_info(public_key, private_key)
                 
 
            elif algorithm == "DSA":
                try:
                                         
                    key = session.get_key(label= key_label)
                    sys.exit(f"Key with label='{key_label}' already exists.")
                except pkcs11.exceptions.NoSuchKey:
                        pass
                except pkcs11.exceptions.MultipleObjectsReturned:
                        sys.exit(f"Multiple keys found with label='{key_label}'.")
 
                # For DSA, we need to generate a public and private key pair
                args = parse_args()
                    #prime = args["prime"]
                 
 
                parameters = session.generate_domain_parameters(pkcs11.KeyType.DSA, 1024)
                public_DSA, private_DSA = parameters.generate_keypair(label=key_label, store=True)
 
                print_dsa_key_info(public_DSA, private_DSA)
                     
    finally:
       lib.reinitialize()
         
     
 
# Create and define a table for the key information
console = Console()
 
table = Table(show_header=True, header_style="red", show_lines=True, title="Key Information")
table.add_column("Attribute", style="dim", width=25, justify="center")
 
        # Add a column for the key information
table.add_column("Value", style="bright", width=20, justify="center")
table.title_style = "italic"
table.border_style = "green"
 

    
# Copy a key 
def key_copy(token_label, key_label, new_label, pin, algorithm):
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin=pin) as session:
            # Verify if key_label exists
            try:
               if algorithm in ["AES", "3DES"]:
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
 
def delete_key(token_label, key_label, pin):
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin=pin) as session:
            key = session.get_key(label=key_label)
            key.destroy() 
            console = Console()
            table = Table(show_header=True, header_style="bold red", show_lines=True, title=":thumbs_up: Key Deleted:  ", title_style="Bold", border_style="green", style="bright", width=50)
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


 # Sign data with a key

def sign_data(token_label, key_label, input_file_path, signature_path, algorithm, pin):
    try:
        token = lib.get_token(token_label=token_label)
        
        data = open(input_file_path, 'rb').read()
        
        with token.open(rw=True, user_pin=pin) as session:
          if algorithm in ["AES", "3DES"]: 
            key = session.get_key(label=key_label)
            signature = key.sign(data)
            
            print(f'File successfully signed: {signature.hex()} (in hex format)')
        
          elif algorithm in ["RSA", "DSA", "ECDSA"]:
            private_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
            signature = private_key.sign(data)
            print(f'File successfully signed: {signature.hex()} (in hex format)')    
        
        with open(signature_path, 'wb') as sig_file:
            sig_file.write(signature)
            print('Signature written to:'+ signature_path + ' (in byte format)' )
            
    except pkcs11.NoSuchKey:
        sys.exit(f"No key found with label='{key_label}'.")


# Verify signed data with a key
def verify_data(token_label, key_label, algorithm, input_file_path, signature_path):
    try:
        # Load data and signature from files
        with open(input_file_path, 'rb') as data_file, open(signature_path, 'rb') as sig_file:
            data = data_file.read()
            signature = sig_file.read()

        # Access the token and find the public key
        with lib.get_token(token_label=token_label).open() as session:
            if algorithm in ['RSA', 'ECDSA', 'DSA']:
                public_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)
                # Verify the signature
                verification_result = public_key.verify(data, signature)
                
                # Find the private key to make reference
                private_key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
                
                verification_confirmation_asymmetric(verification_result, private_key)
            
            if algorithm in ['AES', '3DES']:
                key = session.get_key(label=key_label)
                
                verification_result = key.verify(data, signature)
                
                verification_confirmation_symmetric(verification_result, key)
                         
            else:
                logger.error(f"Unsupported algorithm: {algorithm}")
                

    except TokenNotPresent:
        logger.error(f"No token found with label '{token_label}'.")
    except NoSuchKey:
        logger.error(f"No key found with label '{key_label}'.")
    except FileNotFoundError:
        logger.error("Data or signature file not found.")
    except Exception as e:
        logger.exception(f"An error occurred during verification: {str(e)}")

    
# Encrypt a data with a key

def encrypt_data(token_label, key_label, pin, algorithm, input_file_path, output_file_path):
    try:
        token = lib.get_token(token_label=token_label)
        
        with token.open(rw=True, user_pin=pin) as session:  
            input_file = input_file_path
            output_file = output_file_path 
                  
            if algorithm in ["AES", "3DES"]:

             iv = session.generate_random(128)
             key = session.get_key(label=key_label)
        
        
        # Encrypt the file contents and output it to a file.
             buffer_size = 8192          
             
             with open(input_file, "rb") as input, open(output_file, "wb") as output:
          
                  chunks = iter(lambda: input.read(buffer_size), b'')
            
                  for chunk in key.encrypt(chunks, mechanism_param =iv, buffer_size=buffer_size):
                    output.write(chunk)
                    encrypt_confirmation(token, input_file, output_file, key_label)
                
         
                    
            
            if algorithm in ["RSA"]:
                    key = session.get_key(object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY, label=key_label)

                    # Encrypt the file contents and output it to a file.
                    with open(input_file, "rb") as input, open(output_file, "wb") as output_file:
                        plaintext = input.read()
                        ciphertext = key.encrypt(plaintext)
                        output_file.write(ciphertext)                        
                    encrypt_confirmation(token, str(input_file), output_file, key_label)
                        
                        
    except pkcs11.NoSuchKey:
                logger.error(f"No key found with label='{key_label}'.")
    
    except Exception as e:
                logger.exception(f"An error occurred while encrypting the file: {e}")
            

def decrypt_data(token_label, key_label, encrypted_path, output_file_path, algorithm, pin):
    try: 
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin = pin) as session:
            if algorithm in ["AES", "3DES"]:    
                with open(encrypted_path, "rb") as encrypted_file:            
                    iv = session.generate_random(128)
                    ciphertext = encrypted_file.read()
                    
                    # find key
                    key = session.get_key(label=key_label)
                    # decrypt data using key. 
                    plaintext = key.decrypt(ciphertext, mechanism_param=iv)
                    # write decrypted data to file.
                with open(output_file_path, "wb") as decrypted_file:
                    decrypted_file.write(plaintext)
                    decrypt_confirmation(token, key_label, encrypted_path, output_file_path)
                        
            elif algorithm in ["RSA"]:
                key = session.get_key(object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=key_label)
                with open(encrypted_path, "rb") as encrypted_file:
                    ciphertext = encrypted_file.read()
                    plaintext = key.decrypt(ciphertext)
                
                with open(output_file_path, "wb") as decrypted_file:
                    decrypted_file.write(plaintext)
                    decrypt_confirmation(token, key_label, encrypted_path, output_file_path)
                        
    except pkcs11.NoSuchKey:
        print(f"No key found with label='{key_label}'.")
    except pkcs11.exceptions.FunctionFailed:
        print("Function failed")
    except Exception as e:
        print(f"An error occurred while decrypting the file: {e}")
                        
    
    
## Printing Functions ###
 
 # For encrypt_data function 
 
def encrypt_confirmation(token, input_file, output_file, key_label):
    table = Table(show_header=True, header_style="bold red", show_lines=True, title=":thumbs_up: File Encrypted:  ", title_style="Bold", border_style="green", style="bright", width=150)
    table.add_column("Token Label")
    table.add_column("File to encrypt")
    table.add_column("Encrypted File")
    table.add_column("Key Label")
    table.add_row(token.label, str(input_file), str(output_file), key_label)
            
    console = Console()
    console.print(table) 
            

def decrypt_confirmation(token, key_label, input_file_path, output_file_path):
    table = Table(show_header=True, header_style="bold red", show_lines=True, title=":thumbs_up: File Decrypted:  ", title_style="Bold", border_style="green", style="bright", width=150)
    table.add_column("Token Label")
    table.add_column("File to decrypt")
    table.add_column("Decrypted File")
    table.add_column("Key Label")
    table.add_row(token.label, input_file_path, output_file_path, key_label)
            
    console = Console()
    console.print(table)
            
 # For verify_data function using symmetric keys             
def verification_confirmation_symmetric(verification_result, key):


 table = Table(show_header=True, header_style="bold",border_style= "green",title="File Verified :thumbs_up:", style="Bold", show_lines=True)
 table.add_column("Signature Verification Result")
 table.add_column("Signed by Secret Key Label") 
 table.add_row(str(verification_result), key.label)
 console = Console()

 console.print(table)              
 
 # For verify_data function using asymmetric keys
def verification_confirmation_asymmetric(verification_result, private_key):
    table = Table(show_header=True, header_style="bold",border_style= "green", style="Bold", show_lines=True)
    table.add_column("Signature Verification Result")
    table.add_column("Signed by Public Key Label")
    
    table.add_row(str(verification_result),private_key.label)
    console = Console()
    console.print(table)
                
# Create and define a table for the key information
console = Console()
 
table = Table(show_header=True, header_style="red", show_lines=True, title="Key Information")
table.add_column("Attribute", style="dim", width=25, justify="center")
 
        # Add a column for the key information
table.add_column("Value", style="bright", width=20, justify="center")
table.title_style = "italic"
table.border_style = "green"
 
     
# Print key information


# print AES info ##

def print_aes_key_info(key):
# Create and define a table for the key information
  console = Console()
 
  table = Table(show_header=True, header_style="red", show_lines=True, title="Key Information")
  table.add_column("Attribute", style="dim", width=25, justify="center")
 
        # Add a column for the key information
  table.add_column("Value", style="bright", width=20, justify="center")
  table.title_style = "italic"
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
        
  for attribute, value in key_info.items():
    table.add_row(attribute, str(value))
    table.title = "AES Key Information"
  console.print(table)
 
 ## print RSA info ##
 
def print_rsa_key_info(public, private):
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
        #"SENSITIVE": public.__getitem__(pkcs11.Attribute.SENSITIVE),       ## NOT ALLOWED IN PUBLIC KEY
        #"EXTRACTABLE": public.__getitem__(pkcs11.Attribute.EXTRACTABLE),   ## NOT ALLOWED IN PUBLIC KEY 
       #"WRAP WITH TRUSTED": public.__getitem__(pkcs11.Attribute.WRAP_WITH_TRUSTED),  ## NOT ALLOWED IN PUBLIC KEY        
        #"DECRYPT": public.__getitem__(pkcs11.Attribute.DECRYPT),  ## NOT ALLOWED IN PUBLIC KEY        
        #"UNWRAP": public.__getitem__(pkcs11.Attribute.UNWRAP), ## NOT ALLOWED IN PUBLIC KEY
        #"SIGN": public.__getitem__(pkcs11.Attribute.SIGN), ## NOT ALLOWED IN PUBLIC KEY
        
    
    private_info = {"EXTRACTABLE": private.__getitem__(pkcs11.Attribute.EXTRACTABLE),
                    "WRAP WITH TRUSTED": private.__getitem__(pkcs11.Attribute.WRAP_WITH_TRUSTED),                    
                    "DECRYPT": private.__getitem__(pkcs11.Attribute.DECRYPT),                    
                    "UNWRAP": private.__getitem__(pkcs11.Attribute.UNWRAP),
                    "SIGN": private.__getitem__(pkcs11.Attribute.SIGN),
                    #"VERIFY": private.__getitem__(pkcs11.Attribute.VERIFY)   ## NOT ALLOWED IN PRIVATE KEY
                    #"LABEL": private.__getitem__(pkcs11.Attribute.LABEL),  ## NOT ALLOWED IN PRIVATE KEY
                    #"TOKEN": private.__getitem__(pkcs11.Attribute.TOKEN),  ## NOT ALLOWED IN PRIVATE KEY
                    #"KEY TYPE": private.__getitem__(pkcs11.Attribute.KEY_TYPE), ## NOT ALLOWED IN PRIVATE KEY
                    #"KEY SIZE": private.__getitem__(pkcs11.Attribute.MODULUS_BITS),  ## NOT ALLOWED IN PRIVATE KEY
                    #"TRUSTED": private.__getitem__(pkcs11.Attribute.TRUSTED), ## NOT ALLOWED IN PRIVATE KEY
                    #"PRIVATE": private.__getitem__(pkcs11.Attribute.PRIVATE), ## NOT ALLOWED IN PRIVATE KEY
                    #"MODIFIABLE": private.__getitem__(pkcs11.Attribute.MODIFIABLE), ## NOT ALLOWED IN PRIVATE KEY
                    #"SENSITIVE": public.__getitem__(pkcs11.Attribute.SENSITIVE), ## NOT ALLOWED IN PRIVATE KEY
                    #"ENCRYPT": private.__getitem__(pkcs11.Attribute.ENCRYPT), ## NOT ALLOWED IN PRIVATE KEY
                    #"WRAP": private.__getitem__(pkcs11.Attribute.WRAP), ## NOT ALLOWED IN PRIVATE KEY
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
        #"TOKEN": private_DSA.__getitem__(pkcs11.Attribute.TOKEN),
        #"KEY TYPE": private_DSA.__getitem__(pkcs11.Attribute.KEY_TYPE),
        #"PRIME": private_DSA.__getitem__(pkcs11.Attribute.PRIME),   
        #"SUBPRIME": private_DSA.__getitem__(pkcs11.Attribute.SUBPRIME),
       # "BASE": private_DSA.__getitem__(pkcs11.Attribute.BASE),
        #"VALUE": private_DSA.__getitem__(pkcs11.Attribute.VALUE), ## Removed because it is not allowed in private key / leaks priv key.
        #"LOCAL": private_DSA.__getitem__(pkcs11.Attribute.LOCAL),}
        #"EXTRACTABLE": private_DSA.__getitem__(pkcs11.Attribute.EXTRACTABLE),
        #"SIGN": private_DSA.__getitem__(pkcs11.Attribute.SIGN),
        #"VERIFY": private_DSA.__getitem__(pkcs11.Attribute.VERIFY)
        #"SENSITIVE": private_DSA.__getitem__(pkcs11.Attribute.SENSITIVE)
  
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
    table = Table(show_header=True, header_style="bold red", show_lines=True, title="Key Copied Successfully:", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Copied Key Label")
    table.add_column("New Key Label")
    table.add_row(token_label, key_label, new_label)
    console.print(table)       
                    

# For list_keys function

def print_public_keys(token_label,public_keys):
    console = Console()
    table = Table(show_header=True, header_style="bold red", show_lines=True, title="Public Keys Found:", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")    
    table.add_column("Key Type")
    table.add_column("Key Size")
    
    table.add_row(token_label, public_keys.label, str(public_keys.key_type), str(public_keys.key_length)) 
    console.print(table)                
           
def print_private_keys(token_label, private_keys):
    console = Console()
    table = Table(show_header=True, header_style="bold red", show_lines=True, title= "Private Keys Found", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")
    table.add_column("Key Type")
    table.add_column("Key Size")
    
    table.add_row(token_label, private_keys.label, str(private_keys.key_type), str(private_keys.key_length)) 
    console.print(table)   
                    
           
def print_secret_keys(token_label, secret_keys):
    console = Console()
    table = Table(show_header=True, header_style="bold red", show_lines=True,  title= "Secret Keys Found", title_style="italic", border_style="green", style="bright", width=100)
    table.add_column("Token Label")
    table.add_column("Key Label")    
    table.add_column("Key Type")
    table.add_column("Key Size")
    
    table.add_row(token_label, secret_keys.label, str(secret_keys.key_type), str(secret_keys.key_length)) 
    console.print(table)
       
            
            
  



# Call to main function
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(repr(e))
        raise e
