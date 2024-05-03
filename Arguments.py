# Custom module to parse arguments for other operations using PKCS#11 within an nCipher Hardware Security Module (HSM).
# Tested and validated on nCipher nShield HSM 5c.
# Developed by Armando Montero.

import argparse
import logging
import pkcs11

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(program_name := "Encryption/Decryption  ")


class Arguments:
    '''Class to parse the command line arguments for the program'''
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="PKCS#11 Tool for nCipher Hardware Security Modules", add_help=True, allow_abbrev=True, usage="%(prog)s [options] --lib-path --token-label --pin --key-label / --new-label --key-length --input-path / --output-path --attribute --algorithm --curve (only for EC) --iv (only for AES)")
        self.setup_arguments()

    def setup_arguments(self):
        self.parser.add_argument("--encrypt", "-enc", action='store_true', help="Encrypt the data")
        self.parser.add_argument("--decrypt", "-dec", action='store_true', help="Decrypt the data")
        self.parser.add_argument("--generate", "-g", action='store_true', help="Generate a key")
        self.parser.add_argument("--copy", "-c", action='store_true', help="Copy a key")
        self.parser.add_argument("--delete", "-d", action='store_true', help="Delete a key")
        self.parser.add_argument("--list", "-l", action='store_true', help="List all keys")
        self.parser.add_argument("--find", "-f", action='store_true', help="Find a key")
        self.parser.add_argument("--modify", "-m", action='store_true', help="Modify a key")
        self.parser.add_argument("--sign", "-s", action='store_true', help="Sign the data")
        self.parser.add_argument("--verify", "-v", action='store_true', help="Verify the data")
        self.parser.add_argument("--wrap", "-w", action='store_true', help="Wrap a key")
        self.parser.add_argument("--unwrap", "-uw", action='store_true', help="Unwrap a key")
        self.parser.add_argument("--export-key", "-ex", action='store_true', help="Export a key")        
        self.parser.add_argument("--wrapping-key", "-wk", type = str, help="Wrapping key to use for wrapping ops")
        self.parser.add_argument("--key-to-wrap", "-ktw", type = str, help="Unwrapping key to use for unwrapping ops")
        self.parser.add_argument("--list-keys", "-lk", action='store_true', help="List all keys")
        self.parser.add_argument("--list-tokens", "-lt", action='store_true', help="List all tokens")
        self.parser.add_argument("--find-token", "-ft", action='store_true', help="Find a token")
        self.parser.add_argument("--signature-path", "-sp", type=str, required=False, help="Path to the signature file")
        self.parser.add_argument("--lib-path", "-lib", type=str, required=False, help="Path to the PKCS#11 library", default ="C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll")
        self.parser.add_argument("--token-label", "-t", type=str, required=False, help="Label of the token", default = "loadshared accelerator")
        self.parser.add_argument("--pin", "-p", type=str, required=False, help="PIN of the token", default = "1234")
        self.parser.add_argument("--key-label", "-k", type=str, required=False, help="Label of the key")
        self.parser.add_argument("--new-label", "-nl", type=str, required=False, help="New label of the key")
        self.parser.add_argument("--key-length", "-kl", type=int, required=False, help="Length of the key", default = 256)
        self.parser.add_argument("--input-path", "-i" , type=str, required=False, help="Path to the input file")
        self.parser.add_argument("--output-path", "-o", type=str, required=False, help="Path to the output file")
        self.parser.add_argument("--algorithm", "-alg", type=str, choices=['AES', '3DES', 'RSA', 'EC', 'DSA'], default='AES', help="Algorithm to use")
        self.parser.add_argument("--curve", "-crv", type=str, default='secp521r1', help="Curve to use")
        self.parser.add_argument("--iv", type=int, default=128, help="Initialization vector (size in bits)")
        self.parser.add_argument("--attribute", "-a", action = StoreAttributeAction, type=str, nargs='+', default= [],  required=False, help="Attribute to set")




    def parse(self):
        return self.parser.parse_args()
    
# Custom action to store the attributes.

class StoreAttributeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values is not None:
            for value in values:
                attr, bool_value = value.split('=')
                bool_value = bool_value.lower() in ['yes', 'true', 't', 'y', '1']
                setattr(namespace, self.dest, getattr(namespace, self.dest, []) + [(attr, bool_value)])

    def parse_attributes(self, attribute_values, template):
        for attr, value in attribute_values:
            # Convert the attribute name to its corresponding attribute value
            attr = getattr(pkcs11.Attribute, attr)

            # Apply the attribute value to the template
            template[attr] = value