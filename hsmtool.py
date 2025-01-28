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

Description & Usage:

Creates or uses an exsisting an RSA Key Pair on an nShield HSM device 
Wraps the RSA private key with an exisiting or newly generated AES wrapping key. 
File is exported in encrypted binary format.
Generates a CSR using the RSA key stored in HSM via OpenSSL with nfkm engine.

Instructions:
  * Enter the RSA key label (e.g., mykey)
  * Enter the AES wrapping key label (e.g., wrappingkey)
    * Enter the token label (e.g., loadshared accelerator)
        * Enter the token pin   
            * Enter the key size (e.g., 2048 or 4096)
            * Do you want the public key to be a wrapping key? (y/n)
            * Public key is generated or exisiting key is used
            * Private key is generated or exisiting key is used
            * AES Secret key is generated or exisiting key is used
            * RSA Private key is wrapped
            * Wrapped key material can be saved to file (custom path can be given or default is current working directory) 
            * CSR is generated with OpenSSL 
            * CSR is signed using the private key
            * CSR is saved as file (custom path can be given or default is current working directory)

Supported OS: Windows, Linux
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
            command = 'nfkminfo -l'
            output = subprocess.check_output(command, 
                shell=True, text=True, env=env
            )
            print('Available keys:')
            print(output)
        elif os_type == 'linux' or os_type == 'linux2':

            output = subprocess.check_output(['/opt/nfast/bin/nfkminfo', '-l'], text=True, env=env)
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
    """ Function for user input with an optional default value."""
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default

def format_key_output_rsa(key, key_type):
    '''Format the RSA key output for display'''

    key_info = f"{key_type} Key:\n"
    key_info += f"  Label: {getattr(key, 'label', 'N/A')}\n"
    key_info += f"  Key Size: {getattr(key, 'key_size', MODULUS_BITS)}-bit\n"
    key_info += f"  Key Type: {key.__class__.__name__}\n"
    key_info += f"  Exponent: {getattr(key, 'public_exponent', '65537')}\n"
  
    return key_info

def format_key_output_aes(key, key_type):
    
    '''Format the AES key output for display'''

    key_info = f"{key_type} Key:\n"
    key_info += f"  Label: {getattr(key, 'label', 'N/A')}\n"
    key_info += f"  Key Size: {getattr(key, 'key_length',)}-bit\n"
    key_info += f"  Key Type: {key.__class__.__name__}\n"

    return key_info


def sanitize_filename(filename):
    ''' Remove invalid characters for Windows filenames '''
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


# If you're using a virtual environment, make sure pkcs11 is installed there
# You can use pip list to see the installed packages
# Install python-pkcs11 by executing pip install python-pkcs11. 

# If there's a problem with your Python installation, you might need to reinstall Python or the python module.

# This script is used to generate a new RSA keypair on a nShield HSM Edge device.

# The following environment variables must be set:
#   - PKCS11_MODULE_PATH: the path to the pkcs11 module
#   - NFAST_HOME: the path to the nFast directory (e.g., C:\Program Files\nCipher\nfast\ or /opt/nfast/)
#  -  OPENSSL_ENGINES: the path to the OpenSSL engines directory (e.g., C:\Program Files\nCipher\nfast\openssl\lib\engines-1.1 or /opt/nfast/openssl/lib/engines-1.1)

# You may need to set the following environment variables:
#   - Add %NFAST_HOME%\bin to your PATH environment variable. 
# (Windows) Go to Settings > Environment Variables > System Variables > Path > Edit > New > %NFAST_HOME%\bin = C:\Program Files\nCipher\nfast\bin
# (Linux) export PATH=$PATH:/opt/nfast/bin

# Get the current environment variables
env = os.environ.copy()

# Set the required environment variables. Modify as needed. 

os_type = sys.platform

if os_type == 'win32' or os_type == 'cygwin':
    os.environ['PKCS11_MODULE_PATH'] = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'
    os.environ['CKNFAST_LOADSHARING'] = '1'
    os.environ['CKNFAST_FAKE_ACCELERATOR_LOGIN'] = '1'
    os.environ['NFAST_HOME'] = 'C:\\Program Files\\nCipher\\nfast\\'
    os.environ['OPENSSL_ENGINES'] = 'C:\\Program Files\\nCipher\\nfast\\openssl\\lib\\engines-1.1'
    env["PATH"] = env["PATH"] + ";C:\\Program Files\\nCipher\\nfast\\bin;C:\\Program Files\\nCipher\\nfast\\openssl\\bin"

elif os_type == 'linux' or os_type == 'linux2':
    os.environ['PKCS11_MODULE_PATH'] = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
    os.environ['CKNFAST_LOADSHARING'] = '1'
    os.environ['CKNFAST_FAKE_ACCELERATOR_LOGIN'] = '1'
    os.environ['NFAST_HOME'] = '/opt/nfast/'
    os.environ['OPENSSL_ENGINES'] = '/opt/nfast/openssl/lib/engines-1.1'
    env["PATH"] = env["PATH"] + ":/opt/nfast/bin:/opt/nfast/openssl/bin"

else:
    print("Unsupported OS type")
    sys.exit(1)

# Define the pkcs11 module library
lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])


# The following environment variables are optional:
# They can also be placed in the cknfastrc file in the nfast directory.

os.environ['CKNFAST_OVERRIDE_SECURITY_ASSURANCE'] = 'all'
#os.environ['CKNFAST_DEBUG'] = '10'
#os.environ['CKNFAST_DEBUGFILE'] = '/opt/nfast/pkcs11_debug.log'


# Prompt for the RSA key label
PKCS11_KEY_LABEL = get_user_input("Enter the key label: ", default="rsa_key")

# Prompt for the AES wrapping key label
PKCS11_WRAPPING_KEY_LABEL = get_user_input("Enter the wrapping key label: ", default="aes_wrapping_key")

# Prompt for the token label
PKCS11_TOKEN_LABEL = get_user_input("Enter the token label: ", default="loadshared accelerator")

# Prompt for the pin
PKCS11_PIN = get_user_input("Enter the token pin: ", default="1234")

# Get the token using the provided label
token = lib.get_token(token_label=PKCS11_TOKEN_LABEL)

# Prompt for the key size
key_size = int(get_user_input("Enter the key size (2048 or 4096): ", default=2048))
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
        # Verify if key exists.
        key = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, label=PKCS11_KEY_LABEL)
        
        print(f"Key pair with label '{PKCS11_KEY_LABEL}' already exists, wrapping private key portion instead...")
        time.sleep(2)

        # Store the private key in a variable
        private = key

    except pkcs11.exceptions.NoSuchKey:
        print(f"Key with label '{PKCS11_KEY_LABEL}' does not exist. Generating a new key pair... \n")
        time.sleep(1)

        # Generate the key pair
        public, private = session.generate_keypair(pkcs11.KeyType.RSA, key_size, public_template=public_key_template, 
                                                   private_template=private_key_template, 
                                                   label=PKCS11_KEY_LABEL)
        
        # Print the public key information
        key_info = format_key_output_rsa(public, "Public")
        print(key_info)
        
        # Print the private key information
        key_info = format_key_output_rsa(private, "Private")
        print(key_info)
        
        print("Key pair generated successfully! \n")
        time.sleep(1)
    
    try:
        # Verify if wrapping key exists.
        wrapping_key = session.get_key(label=PKCS11_WRAPPING_KEY_LABEL)
        if wrapping_key:
            print(f"Wrapping key with label: '{wrapping_key.label}' already exists. \n")
            time.sleep(1)
            print(f'Proceeding with wrap operation...')
            time.sleep(1)
            print(f"Wrapping key label: '{PKCS11_KEY_LABEL}' key with wrapping key: '{PKCS11_WRAPPING_KEY_LABEL}'... ")
            time.sleep(2)

        # Wrap the RSA private key
        wrapped_key = wrapping_key.wrap_key(private, mechanism=pkcs11.Mechanism.AES_KEY_WRAP_PAD) # Required mech to wrap private RSA keys.
    
    except pkcs11.exceptions.NoSuchKey:
        # Generate the wrapping key if it doesn't exist
        print('Wrapping key does not exist. Generating a new wrapping key...')
        time.sleep(1)

        wrapping_key = session.generate_key(pkcs11.KeyType.AES, 256, label=PKCS11_WRAPPING_KEY_LABEL, store=True) # store=True is required otherwise it creates ephemeral keys which we do not want in a wrapping/unwrapping scenario.
        time.sleep(1)
        print('Wrapping key generated successfully! \n')

        # Print the wrapping key information
        key_info = format_key_output_aes(wrapping_key, "Wrapping")
        print(key_info)        
        time.sleep(1)

        # Wrap the RSA private key
        wrapped_key = wrapping_key.wrap_key(private, mechanism=pkcs11.Mechanism.AES_KEY_WRAP_PAD) # Required mech to wrap private RSA keys.
        print('Wrapping RSA private key...\n')
        time.sleep(2)
    
    if wrapped_key:
        print(f"Private key label: '{PKCS11_KEY_LABEL}'successfully wrapped using wrapping key: '{PKCS11_WRAPPING_KEY_LABEL}'! \n")
        time.sleep(1)
    else:
        print('Error generating wrapping key')
        sys.exit(1)


# Prompt to save the wrapped encrypted key material to a file

save_to_file = get_user_input('Save the wrapped key material to a file? (y/n):', default='y').strip().lower()

# Sanitize the PKCS11_KEY_LABEL
sanitized_label = sanitize_filename(PKCS11_KEY_LABEL)

# Get the current time for timestamping the filename
current_time = time.strftime("%m_%d_%Y-%H_%M")

if save_to_file == 'y':
    file_path = input("Enter the file name or full path to save the wrapped key (e.g C:\Temp or /home/. Default is current working directory):").strip()

    # Default to the current working directory if no path is provided
    if not file_path:
        # Save the file in cwd with a timestamped filename
        file_path = os.path.join(os.getcwd(), f"{sanitized_label}_wrapped_key_{current_time}.bin")
    elif file_path:
        # Check if the provided path is a directory
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, f"{sanitized_label}_wrapped_key_{current_time}.bin")
        
        # Create any missing directories in the custom path
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name)
    
    # Write the wrapped key material to the specified file
    with open(file_path, 'wb') as f:
        f.write(wrapped_key)
    print(f'Wrapped key material saved to {file_path}')

    print("Private key wrapped successfully! \n")
    time.sleep(1)
else:
    print("Wrapped key not saved.")
    
 
# Generate a CSR using the public key

# Prompt to create a CSR
csr_bool = input("Do you want to create a CSR using the public key? (y/n): ").strip().lower()

if csr_bool != 'y':
    print('No CSR generated')
    sys.exit('Exiting...')
    
elif csr_bool == 'y':

    key_label = input("Enter the key label (e.g., rsa_key): ").strip()
    appname_ident = extract_appname_ident(key_label)

    if appname_ident:
        print(f"Extracted identifier: {appname_ident} \n")
    else:
        sys.exit("Error: appname_ident not found \n")


     # Use the extracted appname_ident in the OpenSSL command
    command = f'openssl req -new -keyform engine -engine nfkm -key "{appname_ident}" -out {PKCS11_KEY_LABEL}_csr.req'
    print("Running OpenSSL command... \n")
        
    try:
        output = subprocess.check_output(command, shell=True, text=True, env=env)
        print("CSR generated successfully! \n")
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error generating CSR: {e}")
        sys.exit(1)
    
    # Prompt to save the CSR
save_to_file = get_user_input('Save the CSR to a file? (y/n): ', default='y').strip().lower()
if save_to_file == 'y':
    file_path = input("Enter the full path location to save the CSR (e.g C:\Temp\ or /home/ default is current working directory): ").strip()
    
    # Default to the current working directory if no path is provided
    if not file_path:
        file_path = os.path.join(os.getcwd(), f"{sanitized_label}_csr.req")
    else:
        # Check if the provided path is a directory
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, f"{sanitized_label}_csr.req")
        
        # Create any missing directories in the custom path
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name)
    
    # Move the CSR file to the specified path
    os.rename(f'{PKCS11_KEY_LABEL}_csr.req', file_path)
    print(f'CSR saved to {file_path}')
else:
    print("CSR not saved. Exiting...")
    sys.exit(1)


# If SAN is required, add the -reqexts SAN option to the command and provide the SAN details in the config file
# (C:\Program Files\nCipher\nfast\openssl\openssl.cnf)
# -reqexts SAN \-config <(cat /opt/nfast/openssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com"))
