# p11-tool

![image-2024-5-1_14-47-20](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/2198e943-fa86-4d6c-a7ec-2b704f5b38e9)

This Python program manages a robust PKCS#11 infrastructure using HSM's, designed for various cryptographic operations including encryption, decryption, key management, and more. It supports multiple cryptographic algorithms like AES, 3DES, DSA, and EC, ensuring compatibility with nCipher, NitroKey, and Luna Hardware Security Modules (HSM). The script leverages custom modules and standard libraries to provide a comprehensive tool for cryptographic management. My project aims to facilitate secure cryptographic processes and hardware interactions. This tool integrates custom modules such as EncryptDecrypt, ManagementOperations, and SignVerify, along with standard libraries to ensure robust and secure cryptographic processes. In short, this tool serves as a valuable resource for any seeking to learn and enhance security practices in cryptographic environments.

Supported operations on CKA_SECRET_KEY, CKA_PRIVATE_KEY, and CKA_PUBLIC_KEY objects. 

It can perform the following operations:

- Generate
- Copy
- Delete
- Wrap
- Unwrap
- Encrypt
- Decrypt
- Sign 
- Verify
- Export (public key)

Note: 
By default, the nCipher HSM PKCS#11 DLL is utilized and defined in args.lib_path; make sure you change to the desired DLL. 

Syntax Examples:

# Generating Keys

- AES
   
  python3 p11-tool.py --generate --algorithm AES --key-label AES_KEY --key-length 256 --token-label 'loadshared accelerator'

- 3DES (DES3)
  python3 p11-tool.py --generate --algorithm DES3 --key-label DES3_KEY --key-length 1024 --token-label 'loadshared accelerator'
  
- RSA
   
  python3 p11-tool.py --generate --algorithm RSA --key-label RSA_KEY --key-length 2048 --token-label 'loadshared accelerator'

- EC
   
  python3 p11-tool.py --generate --algorithm EC --key-label EC_KEY --curve secp521r1 --token-label 'loadshared accelerator'

- DSA
  
  python3 p11-tool.py --generate --algorithm  --key-label DSA_KEY --token-label 'loadshared accelerator'

Note: 
You can create keys with custom attributes by adding the --attribute or -attr flag allowed values:

VALUE = y/n or yes/no or TRUE/FALSE (boolean)

Example --attribute EXTRACTABLE=yes MODIFIABLE=yes SIGN=y VERIFY=y WRAP=n UNWRAP=no ENCRYPT=y DECRYPT=no WRAP_WITH_TRUSTED=no

If you do not define all the attributes when using the --attribute argument it will automatically set that attribute to TRUE or if no attributes are given via --attribute the key will use a default template. 

# Copying keys

To copy a key you will need to give the key label of the key we want to copy, the algorithm, the new key label, and the token label where the key resides. 

python3 p11-tool.py --copy --key-label RSA_KEY  --new-label <NEW_KEY_LABEL> --algorithm RSA --token-label 'loadshared accelerator' --pin (if required for Operator Card sets or Soft cards, module protected keys use a fake pin such as 1234)


# Deleting keys

To delete keys you will need to specify the key, token label, and the algorithm used for that key you want to delete. This is due to how SECRET KEYS vs PUB/PRIV keys are found. 

python3 p11-tool.py --delete --key-label RSA_KEY --algorithm RSA --token-label 'loadshared accelerator' 

The same concept can be applied to EC, AES, and DSA keys. 


# Encrypt and Decrypt

To encrypt data we will need to give out the following arguments:

Encrypt 
- AES
  
  python3 p11-tool.py --encrypt --key-label <AES_KEY_LABEL> --algorithm AES --input-path "C:\EncryptME.txt" --output-path "C:\EncryptedFile" --token-label 'loadshared accelerator' --iv 128 (iv only for Stream Cipher algorithms like AES/DES3)

- RSA
  
  python3 p11-tool.py --encrypt --key-label <RSA_KEY_LABEL> --algorithm RSA --input-path "C:\EncryptME.txt" --output-path "C:\EncryptedFile" --token-label 'loadshared accelerator'

- DES3
  
  python3 p11-tool.py --encrypt --key-label <DES3_KEY_LABEL>  --algorithm AES --input-path "C:\EncryptME.txt" --output-path "C:\EncryptedFile" --token-label 'loadshared accelerator' --iv 128 (iv only for Stream Cipher algorithms like AES/DES3)

Decrypt 

- AES
  
  python3 p11-tool.py --decrypt --key-label <AES_KEY_LABEL>  --algorithm AES  --input-path  "C:\EncryptedFile" --output-path "C:\Decrypted" --token-label 'loadshared accelerator'  

- RSA
  
  python3 p11-tool.py --decrypt --key-label <RSA_KEY_LABEL> --algorithm RSA --input-path  "C:\EncryptedFile" --output-path "C:\Decrypted" --token-label 'loadshared accelerator'

- DES3
  
  python3 p11-tool.py --decrypt --key-label <DES3_KEY_LABEL>  --algorithm DES3 --input-path  "C:\EncryptedFile" --output-path "C:\Decrypted" --token-label 'loadshared accelerator'

  
# Wrap and Unwrap 
 To wrap a key CKA_EXTRACTABLE=TRUE must be set on the key to extract. We will need to give the following arguments to wrap and unwrap keys from the HSM. 

Wrapping 
- AES
   
   python3 p11-tool.py --wrap --wrapping-key <AES_KEY_LABEL> --key-to-wrap KEY_TO_WRAP_AES --algorithm AES --token-label 'loadshared accelerator' --output-path "C:\Wrapped_KEY_AES"

- DES3

  python3 p11-tool.py --wrap --wraping-key <DES3_KEY_LABEL> --key-to-wrap <KEY_TO_WRAP_LABEL> --algorithm AES --token-label 'loadshared accelerator' --output-path "C:\Wrapped_KEY_DES3"
- RSA
  
  python3 p11-tool.py --wrap --wrapping-key <RSA_KEY_LABEL> --key-to-wrap <KEY_TO_WRAP_LABEL> --algorithm RSA --token-label 'loadshared accelerator' --output-path "C:\Wrapped_KEY_RSA"

- EC
  
  python3 p11-tool.py --wrap --wrapping-key <EC_KEY_LABEL> --key-to-wrap <KEY_TO_WRAP_LABEL> --algorithm EC --token-label 'loadshared accelerator' --output-path "C:\Wrapped_KEY_EC"

- DSA

  python3 p11-tool.py --wrap --wrapping-key <DSA_KEY_LABEL> --key-to-wrap <KEY_TO_WRAP_LABEL> --algorithm DSA --token-label 'loadshared accelerator' --output-path "C:\Wrapped_KEY_DSA"

Unwrapping
- AES
   
   python3 p11-tool.py --unwrap --wrapping-key <AES_KEY_LABEL> --new-label <NEW_LABEL> --algorithm AES --token-label 'loadshared accelerator' --input-path "C:\Wrapped_KEY_AES"

- DES3

  python3 p11-tool.py --unwrap --wrapping-key <DES3_KEY_LABEL> --new-label <NEW_LABEL> --algorithm AES --token-label 'loadshared accelerator' ---input-path "C:\Wrapped_KEY_DES3"
- RSA
  
  python3 p11-tool.py --unwrap --wrapping-key <RSA_KEY_LABEL> --new-label <NEW_LABEL> --algorithm RSA --token-label 'loadshared accelerator' --input-path "C:\Wrapped_KEY_RSA"

- EC
  
  python3 p11-tool.py --unwrap --wrapping-key <EC_KEY_LABEL> --new-label <NEW_LABEL>--algorithm EC --token-label 'loadshared accelerator' --input-path "C:\Wrapped_KEY_EC"

- DSA

  python3 p11-tool.py --unwrap --wrapping-key <DSA_KEY_LABEL> --new-label <NEW_LABEL> --algorithm DSA --token-label 'loadshared accelerator' --input-path "C:\Wrapped_KEY_DSA"



# Signing and Verifying 



   
