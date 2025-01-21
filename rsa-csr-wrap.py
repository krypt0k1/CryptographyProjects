# Import the required modules

import pkcs11
import os
import sys
import time
import re
import subprocess

# Create banner. 

def create_banner(text, width=150, border_char='*'):
    lines = text.strip().split('\n')
    border = border_char * width

    print(border)
    for line in lines:
        print(f"{border_char} {line.ljust(width - 4)} {border_char}")
    print(border)

banner_text = """


DISCLAIMER:
This code is provided for example purposes only.
It is not intended for production use. It has not been tested for security.
nCipher disclaims all warranties, express or implied, including without
limitation, any implied warranties of fitness of this code for any
particular purpose. nCipher shall not be liable for any damages, however
caused, arising out of any use of this code.

Description & Usage:

Creates or uses an exsisting an RSA Key Pair on an nShield HSM device and wraps the private key with an exisiting or newly generated AES key. 
File is exported in encrypted binary format.

  * Enter the key label (e.g., mykey)
    * Enter the token label (e.g., loadshared accelerator)
        * Enter the token pin   
            * Enter the key size (e.g., 2048)
            * Do you want the public key to be a wrapping key? (y/n)
            * Public key is generated
            * Private key is generated
            * Private key is wrapped
            * Wrapped key material can be saved to file (custom path can be given or default is current working directory) 
            * CSR is generated using the public key
            * CSR is signed using the private key
            * CSR is saved as file (custom path can be given or default is current working directory)
            
"""
# Create the banner
create_banner(banner_text)

# Functions 

def extract_appname_ident(key_label):
    """
    Extracts a specific value (e.g., pkcs11_hashvalue####) from the command output
    based on the provided key label.

    Args:
        key_label (str): The key label to search for in the command output.

    Returns:
        str: The extracted value if found, or None if not found.
    """
    try:
        # Get OS type to determine the command to run
        os_type = sys.platform

        if os_type == 'win32' or os_type == 'cygwin':
            output = subprocess.check_output(
                'set PATH=%PATH%;C:\\Program Files\\nCipher\\nfast\\bin && set PATH=%PATH%;C:\\Program Files\\nCipher\\nfast\\openssl && nfkminfo -l', 
                shell=True, text=True
            )
            print('Available keys:')
            print(output)
        elif os_type == 'linux' or os_type == 'linux2':
            output = subprocess.check_output(['/opt/nfast/bin/nfkminfo', '-l'], text=True)
            print('Available keys:')
            print(output)  
        else:
            print("Unsupported OS type")
            return None
    except subprocess.CalledProcessError as e:
        print("Error executing nfkminfo -l:", e)
        return None

       # Regex pattern to match and extract `pkcs11_*` for the given key label
    pattern = rf"key_(pkcs11_[a-zA-Z0-9]+).*`{re.escape(key_label)}'"
   
    # Search for the key label in the command output
    match = re.search(pattern, output)
    if match:
        # Extract the `pkcs11_*` portion
        appname_ident = match.group(1)
        print(f"Extracted appname_ident for '{key_label}': {appname_ident}")
        return appname_ident
    else:
        print(f"No matching key found for label: {key_label}")
        return None


def get_user_input(prompt, default=None):
    """Helper function for user input with an optional default value."""
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default

# Format the key output
def format_key_output(key, key_type):
    '''Format the key output for display'''

    key_info = f"{key_type} Key:\n"
    key_info += f"  Label: {getattr(key, 'label', 'N/A')}\n"
    key_info += f"  Key Size: {getattr(key, 'key_size', MODULUS_BITS)}-bit\n"
    key_info += f"  Key Type: {key.__class__.__name__}\n"
    key_info += f"  Exponent: {getattr(key, 'public_exponent', '65537')}\n"
  
    return key_info

# If you're using a virtual environment, make sure pkcs11 is installed there
# You can use pip list to see the installed packages
# Install python-pkcs11 by executing pip install python-pkcs11. 

# If there's a problem with your Python installation, you might need to reinstall Python or the python module.

# This script is used to generate a new RSA keypair on a nShield HSM Edge device.

# The following environment variables must be set:
#   - PKCS11_MODULE_PATH: the path to the pkcs11 module
#   - PKCS11_TOKEN_LABEL: the label of the token to use
#   - PKCS11_PIN: the pin of the token to use
#   - add %NFAS_HOME%\bin to your PATH environment variable. 
# (Windows) Go to Settings > Environment Variables > System Variables > Path > Edit > New > %NFAST_HOME%\bin = C:\Program Files\nCipher\nfast\bin
# (Linux) export PATH=$PATH:/opt/nfast/bin

# Set the required environment variables.

os.environ['PKCS11_MODULE_PATH'] = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'
os.environ['CKNFAST_LOADSHARING'] = '1'
os.environ['CKNFAST_FAKE_ACCELERATOR_LOGIN'] = '1'
os.environ['%NFAST_HOME%'] = 'C:\\Program Files\\nCipher\\nfast\\bin'

# Defining the pkcs11 module library
lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])


# The following environment variables are optional:
# They can also be placed in the cknfastrc file in the nfast directory.

#os.environ['CKNFAST_OVERRIDE_SECURITY_ASSURANCE'] = 'unwrap_mech;tokenkeys'
#os.environ['CKNFAST_DEBUG'] = '10'
#os.environ['CKNFAST_DEBUGFILE'] = '/opt/nfast/pkcs11_debug.log'


# Prompt for the key label
PKCS11_KEY_LABEL = get_user_input("Enter the key label: ", default="rsa_key")

# Prompt for the wrapping key label
PKCS11_WRAPPING_KEY_LABEL = get_user_input("Enter the wrapping key label: ", default="wrapping_key")

# Prompt for the token label
PKCS11_TOKEN_LABEL = get_user_input("Enter the token label: ", default="loadshared accelerator")

# Prompt for the pin
PKCS11_PIN = get_user_input("Enter the token pin: ", default="1234")

# Get the token using the provided label
token = lib.get_token(token_label=PKCS11_TOKEN_LABEL)

# Prompt for the key size
key_size = get_user_input("Enter the key size (e.g., 2048): ", default=2048)
MODULUS_BITS = key_size

# Check if the key size is valid
if key_size not in [2048, 4096]:
    sys.exit('Error: Key size must be 2048 or 4096')

# Prompt to ask if user wants pubkey to be wrapping key.
WRAPPING_KEY = get_user_input("Do you want the public key to be a wrapping key? (y/n): ", default="n").lower() == 'y'

# The following templates are used to generate a keypair on the HSM. Modify as needed.

public_key_template = {pkcs11.Attribute.TOKEN: True,
                       pkcs11.Attribute.PUBLIC_EXPONENT: 65537, # Public exponent is always 65537. 
                       pkcs11.Attribute.MODULUS_BITS: MODULUS_BITS,
                       pkcs11.Attribute.WRAP: WRAPPING_KEY,
                       pkcs11.Attribute.VERIFY: True,
                       pkcs11.Attribute.MODIFIABLE: True,
                       pkcs11.Attribute.ENCRYPT: True,
                                 
                      }

private_key_template = {pkcs11.Attribute.TOKEN: True,
                        pkcs11.Attribute.PRIVATE: True,
                        pkcs11.Attribute.SENSITIVE: True,
                        pkcs11.Attribute.UNWRAP: True,                        
                        pkcs11.Attribute.MODIFIABLE: True,
                        pkcs11.Attribute.EXTRACTABLE: True,
                        pkcs11.Attribute.DECRYPT: True,
                        pkcs11.Attribute.WRAP_WITH_TRUSTED: False,
                        pkcs11.Attribute.SIGN: True,
                                            
}

# Open a session with the token
with token.open(rw=True, user_pin=PKCS11_PIN) as session:
    try:
        # Try to get the existing private key
        key = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, label=PKCS11_KEY_LABEL)
        
        print(f"Key pair with label '{PKCS11_KEY_LABEL}' already exists, wrapping private key portion instead...")
        time.sleep(2)

        private = key

    except pkcs11.exceptions.NoSuchKey:
        print(f"Key with label '{PKCS11_KEY_LABEL}' does not exist. Generating a new key pair...")
        public, private = session.generate_keypair(pkcs11.KeyType.RSA, key_size, public_template=public_key_template, 
                                                   private_template=private_key_template, 
                                                   label=PKCS11_KEY_LABEL)
        
        # Print the public key information
        key_info = format_key_output(public, "Public")
        print(key_info)
        
        # Print the private key information
        key_info = format_key_output(private, "Private")
        print(key_info)
        
        print("Key pair generated successfully")

    print(f"Wrapping key label: '{PKCS11_KEY_LABEL}' key with wrapping key: '{PKCS11_WRAPPING_KEY_LABEL}'... ")
    time.sleep(2)
    
    try:
        # Try to get the existing wrapping key
        wrapping_key = session.get_key(label=PKCS11_WRAPPING_KEY_LABEL)
        if wrapping_key:
            print(f"Wrapping key with label: '{wrapping_key.label}' already exists.")
            time.sleep(1)
            print(f'Proceeding with wrap operation in 2 seconds...')
            time.sleep(1)

        # Wrap the RSA private key
        wrapped_key = wrapping_key.wrap_key(private, mechanism=pkcs11.Mechanism.AES_KEY_WRAP_PAD) # Required mech to wrap private RSA keys.

        

               
    
    except pkcs11.exceptions.NoSuchKey:
        # Generate the wrapping key if it doesn't exist
        print('Wrapping key does not exist. Generating a new wrapping key...')
        wrapping_key = session.generate_key(pkcs11.KeyType.AES, 256, label=PKCS11_WRAPPING_KEY_LABEL, store=True) # store=True is required otherwise it creates ephemeral keys which we do not want in a wrapping/unwrapping scenario.
    
        # Print the wrapping key information
        key_info = format_key_output(wrapping_key, "Wrapping")
        print(key_info)        
    
    # Wrap the RSA private key
    wrapped_key = wrapping_key.wrap_key(private, mechanism=pkcs11.Mechanism.AES_KEY_WRAP_PAD) # Required mech to wrap private RSA keys.
   
    if wrapped_key:
        print(f"Private key label: '{PKCS11_KEY_LABEL}' wrapped successfully using wrapping key: '{PKCS11_WRAPPING_KEY_LABEL}' ")
        time.sleep(1)
    else:
        print('Error generating wrapping key')
        sys.exit(1)



   # Prompt to save the wrapped key
    save_to_file = input('Save the wrapped key material to a file? (y/n): ').strip().lower()
if save_to_file == 'y':
    file_path = input('Enter the file name or full path to save the wrapped key (default is current directory): ').strip()
    
    # Default to the current working directory if no path is provided
    if not file_path:
        # Create timestamped file name               
        current_time = time.strftime("%Y%m%d-%H%M%S")

        # Save the file in cwd with a timestamped filename
        file_path = os.path.join(os.getcwd(), f"{PKCS11_KEY_LABEL}_wrapped_key_{current_time}.bin")
    else:
        # Check if the provided path is a directory
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, f"{PKCS11_KEY_LABEL}_wrapped_key_{current_time}.bin")
        
        # Create any missing directories in the custom path
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name)
    
    # Write the wrapped key to the specified file
    with open(file_path, 'wb') as f:
        f.write(wrapped_key)
    print(f'Wrapped key saved to {file_path}')

print("Private key wrapped successfully")


# Generate a CSR using the public key

# Prompt if you want to create a CSR
csr_bool = input("Do you want to create a CSR using the public key? (y/n): ").strip().lower()

if csr_bool != 'y':
    print('No CSR generated')
    sys.exit('Exiting...')
    
elif csr_bool == 'y':

    key_label = input("Enter the key label (e.g., rsa_key): ").strip()
    appname_ident = extract_appname_ident(key_label)

    if appname_ident:
        print(f"Extracted identifier: {appname_ident}")
    else:
        sys.exit("Error: appname_ident not found")


     # Use the extracted appname_ident in the OpenSSL command
    command = f'openssl req -new -keyform engine -engine nfkm -key "{appname_ident}" -out csr.pem'
    print("Running OpenSSL command...")
        
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        print("CSR generated successfully!")
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error generating CSR: {e}")
        sys.exit(1)
    
    # Prompt to save the CSR
    save_to_file = get_user_input('Save the CSR to a file? (y/n): ', default='y').strip().lower()
    if save_to_file == 'y':
        file_path = input('Enter the file name or full path to save the CSR (default is current directory): ').strip()
        
        # Default to the current working directory if no path is provided
        if not file_path:
            file_path = os.path.join(os.getcwd(), f"{PKCS11_KEY_LABEL}_csr.pem")
        else:
            # Check if the provided path is a directory
            if os.path.isdir(file_path):
                file_path = os.path.join(file_path, f"{PKCS11_KEY_LABEL}_csr.pem")
            
            # Create any missing directories in the custom path
            dir_name = os.path.dirname(file_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name)
        
        # Move the CSR file to the specified path
        os.rename(f'{PKCS11_KEY_LABEL}_csr.pem', file_path)
        print(f'CSR saved to {file_path}')
    
    elif save_to_file == 'n':
        print("CSR not saved. Exiting...")
        # Capture the output of the command and print it



# If SAN is required, add the -reqexts SAN option to the command and provide the SAN details in the config file
# (C:\Program Files\nCipher\nfast\openssl\openssl.cnf)
# -reqexts SAN \-config <(cat /opt/nfast/openssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com"))
