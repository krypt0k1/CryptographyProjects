import time
import pkcs11
from asn1crypto import pem, x509

# Description
# This script can be utilized to import x.509 certificates to an
# Entrust(nCipher) nShield Hardware Security Module with CKA_TRUSTED.

# *** Important ***
# Before you start:
# 1. Slot 0 can have two different labels depending on the status of the CKNFAST_LOADSHARING variable in the cknfastrc file.
# 2. If disabled slot 0's label is accelerator if enabled it will be loadshared accelerator.
# 3. Verify if the PKCS#11 Security Officer role exists.
#     - Execute cksotool -i from a cmd/shell prompt.
#     - If you do not have the bin path enabled cd to /opt/nfast/bin (Linux) or C:\Program Files\nCipher\nfast\bin\(Windows OS w/ Security World Software v 12.60+).
# 4. You can grab the cardset or softcard hash by executing nfkminfo -c (cardset) or nfkminfo -s (softcard).
# 5. nCipher HSM's have three types of protection methods Module
# (accelerator slot), Operator Card Set (OCS), and Softcards (virtual
# tokens).

# The /opt/nfast/cknfastrc (Linux) or C:\Program
# Files\nCipher\nfast\cknfastrc\ (Windows) file will require modifications
# depending on the desired protection method you want to use.

# Module Protection
# For module protection run ckinfo to ensure the label of slot 0 is the accelerator or loadshared accelerator and modify the script accordingly. No changes to the cknfastrc file are required for module protection.
# ckcerttool (nCipher tool) cannot be used for module protection.

# Operator Card Set (OCS)
# Operator Card Set protection will require two variables to be added to the cknfastrc file
# CKNFAST_CARDSET_HASH=<hash_value_of_OCS>
# CKNFAST_NO_ACCELERATOR_SLOT=1

# Softcards
# Softcards will require an extra step on top of variable modifications. First, open the cknfastrc file.
# CKNFAST_CARDSET_HASH=<hash_value_of_Softcard>
# CKNFAST_LOADSHARING=1

# Procedure

# Must preload the ncipher-pkcs11-so-softcard before running the script.
# 1. Open a cmd prompt and execute the following command:
#    preload -s ncipher-pkcs11-so-softcard cmd  (cmd for Windows, do bash for Linux)
# 2. Within the same cmd prompt run the script.
#    python3 import_x509.py (or full path to the script)
# 3. Close the cmd prompt after confirming the certificate is imported and
# trusted using cklist.


# PEM file handling.
with open('<path/to/cert/certificate.pem>', 'rb') as f:
    der_bytes = f.read()
    if pem.detect(der_bytes):
        type_name, headers, der_bytes = pem.unarmor(der_bytes)

cert = x509.Certificate.load(der_bytes)

# Create the object in HSM

# Define the library path and initialize the library
# Windows library. Use /opt/nfast/toolkits/pkcs11/libcknfast.so for Linux.
LIB = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'
lib = pkcs11.lib(LIB)

# Define the token and open the CKO_SO(Security Officer) session
token = lib.get_token(token_label='<token_label>')  # Define the token label.
session = token.open(so_pin='<pin>', rw=True)  # Define the pin.


# Verify if the certificate exists in the HSM
try:
    cert_obj = session.get_key(
        object_class=pkcs11.ObjectClass.CERTIFICATE,
        label='<certificate_label>')  # Define the certificate label.
    if cert_obj:
        print('Certificate found in the HSM')
        print('Create a new certificate with a different label')
        time.sleep(2)
        print('Exiting...')
        time.sleep(2)
        exit()
except pkcs11.PKCS11Error as e:
    print('Error occurred, check the logs for more information')

# Import the certificate
cert_obj = session.create_object({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                                  pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
                                  pkcs11.Attribute.VALUE: cert.dump(),
                                  # Define the certificate label.
                                  pkcs11.Attribute.LABEL: '<certificate_label>',
                                  pkcs11.Attribute.TOKEN: True,
                                  pkcs11.Attribute.PRIVATE: False,
                                  pkcs11.Attribute.TRUSTED: True
                                  })

print('Imported Certificate information')
print(
    'Imported Certificate label:',
    cert_obj.__getitem__(
        pkcs11.Attribute.LABEL))
print(
    'Imported Certificate type:',
    cert_obj.__getitem__(
        pkcs11.Attribute.CERTIFICATE_TYPE))
print('Token Object Trusted:', cert_obj.__getitem__(pkcs11.Attribute.TRUSTED))
print('Token Object:', cert_obj.__getitem__(pkcs11.Attribute.TOKEN))
print('Token label:', token.label)

# Close the session.
session.close()
