# Description: This script is used to generate, delete, and find AES keys in an Entrust HSM.
import sys
import pkcs11
import argparse
import logging
import os
from rich import print
from rich.table import Table
from rich.console import Console
 
 
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
    Parse command line arguments for the AES key generator.

    Returns:
        dict: A dictionary containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Entrust Python PKCS#11 AES Key Manager/Generator.\n\n"
        "This script is used to generate, delete, and find AES keys in an Entrust HSM.",
        prog="aeskeygen.py",
        usage="%(prog)s [--generate]"
        and '%(prog)s [--find-token] --token-label "loadshared accelerator" --label "default_key_label"\n',
        epilog="Example: %(prog)s --generate --label 'my_key' --key-size 256 --token-label 'loadshared accelerator'\n"
        "       %(prog)s --find-token --token-label 'loadshared accelerator'\n"
        "       %(prog)s --delete --label 'my_key' --token-label 'loadshared accelerator'\n",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True,
        allow_abbrev=True,
    )
    parser.add_argument("-d","--delete",
                        help="Delete the keys with the given version",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-p","--pin",
                        help="The pin of the token to use",
                        required=False,
                        default="1234")  # Default pin if none is provided
    parser.add_argument("-g","--generate",
                        help="generate new keys",
                        required=False,
                        default=False,
                        action="store_true")
    parser.add_argument("-l","--label",
                        help="plaintext label name for the key",
                        required=False,
                        default="default_key_label")  # Default label if none is provided
    parser.add_argument("-k","--key-size",
                        help="size of the key in bits",
                        required=False,
                        type=int,
                        choices=[128, 192, 256],  # Restrict key sizes to 128, 192, or 256
                        default=256)  # Default key size if none is provided
    parser.add_argument("-t","--token-label",
                        help="token label to use",
                        required=False,
                        default="loadshared accelerator")
    parser.add_argument("-f","--find-token",
                        help="find the token with the given label",
                        required=False,
                        action="store_true",
                        default=False)
    parser.add_argument("-s","--find-slots",
                        help="find the slot with the given label",
                        required=False,
                        action="store_true",
                        default=False)
    parser.add_argument("-a", '--attribute',
                        help="Attribute to apply to the key",
                        required=False,
                        default=[],
                        nargs='+',
                        action=StoreAttributeAction)  
     
    args = vars(parser.parse_args())
    return args

# Main function
def main():
    args = parse_args()
    token_label = args["token_label"]    
    key_size = args["key_size"]
    key_label = args["label"]
    pin = args["pin"]
    slot_label = args["find_slots"]
    attribute = args["attribute"]
    

    
# Call the appropriate function based on the arguments
    if args["find_token"]:
        find_token(token_label)
    elif args["generate"]:
        gen_key(token_label, key_label, key_size,template, attribute, pin) # type: ignore        
    elif args["delete"]:
        delete_key(token_label, key_label,pin )        
    elif args["find_slots"]:
        get_slot(slot_label)
        
# Find all available slots
def get_slot(slot_label):
    try:
        slot = lib.get_slots(token_present=True)
        # Format the slot list for printing
        slot_list = [str(s) for s in slot]
        
        table = Table(show_header=True, header_style="red", show_lines=True, title="Slots information")
        table.add_column("Available Slots ðŸ˜Š", style="bright", width=45, justify="center")  # Added emoji smiley face
        table.title_style = "italic"
        table.title = "Slot information"
        table.border_style= "green"
        
        for i, s in enumerate(slot_list, start=1):
            table.add_row(f"{i}. {s}")
        
        console = Console()
        console.print(table)
        
        return slot
    except pkcs11.exceptions.SlotIDInvalid:
        logger.error("No slot found with label='%s'.", slot_label)
    except Exception as e:
        logger.error("An error occurred while finding the slot: %s", str(e))
        raise e


    

# AES Key Template
template = {
            pkcs11.Attribute.TOKEN: "TOKEN",
            pkcs11.Attribute.PRIVATE: "PRIVATE",
            pkcs11.Attribute.MODIFIABLE: "MODIFIABLE",
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
# Grab parse for attribute values. 
args = parse_args()       
attribute_values = args["attribute"]  

# Iterate through the attribute values and apply them to the template

for attr, value in attribute_values:
    # Convert the attribute name to its corresponding attribute value
    attr = getattr(pkcs11.Attribute, attr)

    # Apply the boolean value to the template
    template[attr] = value


# Verify if a key already exists
def gen_key(token_label, key_label, key_size, template, attribute,pin):
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin=pin) as session:
            key = session.get_key(label=key_label)
            sys.exit(f"Key with label '{key_label}' already exists. Please delete it first.")
    except pkcs11.NoSuchKey:
        pass
    except pkcs11.MultipleObjectsReturned:
        sys.exit(f"Multiple keys with label '{key_label}' found. Please delete them first.")
 # Generate a new AES key
    
    token = lib.get_token(token_label=token_label)
    with token.open(rw=True, user_pin=pin) as session:
        key = session.generate_key(pkcs11.KeyType.AES, key_size, label=key_label, template=template)
        print("Key generated successfully.")
        
        # Call print_key_info to display the generated key's information
        print_key_info(key)
        return key     
                   

# Create and define a table for the key information
console = Console()
    
table = Table(show_header=True, header_style="red", show_lines=True, title="Key Information")
table.add_column("Attribute", style="dim", width=25, justify="center")

# Add a column for the key information
table.add_column("Value", style="bright", width=20, justify="center")
table.title_style = "italic"
table.title = "Key Information"
table.border_style = "green"

    
# Print key information
def print_key_info(key):
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
    console.print(table)

###  AES Key Reference ###
# 128-bit AES key /8 = 16 bytes
# 192-bit AES key /8 = 24 bytes
# 256-bit AES key /8 = 32 bytes


# Delete a key

def delete_key(token_label, key_label, pin):
    try:
        token = lib.get_token(token_label=token_label)
        with token.open(rw=True, user_pin=pin) as session:
            key = session.get_key(label=key_label)
            key.destroy()  
            console = Console()
            table = Table(show_header=True, header_style="bold red", show_lines=True, title="Key Deleted", title_style="italic", border_style="green", style="bright", width=50)
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
 
 # Find a token

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
        #table.add_column("Model")
        #table.add_column("Serial Number")

        # Add a row to the table for the token
        table.add_row(token.label, token.manufacturer_id)

        # Print the table
        console.print(table)

    except pkcs11.exceptions.TokenNotPresent:
        sys.exit(f"No token found with label='{token_label}'.")
    except pkcs11.exceptions.MultipleTokensReturned:
        sys.exit(f"Multiple tokens found with label='{token_label}'.")
            
# Call to main function
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(repr(e))
        raise e
