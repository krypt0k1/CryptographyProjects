# Templates for python-pkcs11

import pkcs11
from Arguments import *

####################### TEMPLATE SECTION ############################

args = Arguments().parse()

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

# Default AES Template
default_aes_template = {pkcs11.Attribute.TOKEN: True,
                        pkcs11.Attribute.SENSITIVE: True,
                        pkcs11.Attribute.EXTRACTABLE: False,
                        pkcs11.Attribute.WRAP_WITH_TRUSTED: False,
                        pkcs11.Attribute.ENCRYPT: True,
                        pkcs11.Attribute.DECRYPT: True,
                        pkcs11.Attribute.WRAP: True,
                        pkcs11.Attribute.UNWRAP: True,
                        pkcs11.Attribute.SIGN: True,
                        pkcs11.Attribute.VERIFY: True,
                        pkcs11.Attribute.MODIFIABLE: True}

action = StoreAttributeAction(option_strings=[], dest='attribute', nargs='+', const=None, default=None, type=None, choices=None, required=False, help=None, metavar=None)
action.parse_attributes(args.attribute, aes_template)

# RSA Key Template
 
public_rsa_key_template = {pkcs11.Attribute.TOKEN: "TOKEN",            
            pkcs11.Attribute.MODULUS_BITS: args.key_length,            
            pkcs11.Attribute.ENCRYPT: "ENCRYPT",           
            pkcs11.Attribute.WRAP: "WRAP",           
            pkcs11.Attribute.VERIFY: "VERIFY"}
 
private_rsa_key_template = {pkcs11.Attribute.TOKEN: "TOKEN",
            pkcs11.Attribute.SENSITIVE: "SENSITIVE",            
            pkcs11.Attribute.MODULUS_BITS: args.key_length,            
            pkcs11.Attribute.DECRYPT: "DECRYPT",          
            pkcs11.Attribute.UNWRAP: "UNWRAP",
            pkcs11.Attribute.SIGN: "SIGN"}

action.parse_attributes(args.attribute, public_rsa_key_template)
action.parse_attributes(args.attribute, private_rsa_key_template)

# Default RSA Template
default_rsa_public_template = {pkcs11.Attribute.TOKEN: True,
                               pkcs11.Attribute.MODULUS_BITS: 4096,            
                                pkcs11.Attribute.ENCRYPT: True,
                                pkcs11.Attribute.VERIFY: True,
                                pkcs11.Attribute.WRAP: True,
                                pkcs11.Attribute.MODIFIABLE: True}

default_rsa_private_template = {pkcs11.Attribute.TOKEN: True,
                                pkcs11.Attribute.MODIFIABLE: True,
                                pkcs11.Attribute.EXTRACTABLE: False,                            
                                pkcs11.Attribute.SENSITIVE: True,
                                pkcs11.Attribute.DECRYPT: True,
                                pkcs11.Attribute.UNWRAP: True,
                                pkcs11.Attribute.SIGN: True}

# EC Key Template

private_EC_template= {pkcs11.Attribute.TOKEN: True,                     
                      pkcs11.Attribute.PRIVATE: True,                     
                      pkcs11.Attribute.SIGN: True,
                      pkcs11.Attribute.SIGN_RECOVER: False, 
                      
                      }
public_EC_template = {pkcs11.Attribute.TOKEN: True,                                        
                      pkcs11.Attribute.SIGN: False,                      
                      pkcs11.Attribute.VERIFY: True,
                      pkcs11.Attribute.VERIFY_RECOVER: True,
                      }