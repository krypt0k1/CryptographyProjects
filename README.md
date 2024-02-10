# Public-Key Cryptographic Standards #11 


# Introduction 
______________________________________________________
PKCS #11, short for Public-Key Cryptography Standards #11, is a widely used API (Application Programming Interface) standard that facilitates cryptographic token operations and secure key management. The PKCS series was initially developed by RSA Data Security Inc. during the early 1990s as a set of cryptographic standards to promote secure communication and data encryption. PKCS #11, introduced in this series, was created to standardize interactions with cryptographic hardware devices, such as smart cards and hardware security modules.

Over the years, PKCS #11 has undergone several revisions and updates to accommodate advancements in cryptographic techniques and address emerging security challenges. Notably, RSA Security first published PKCS #11 as version 1.0 in 1995, and later, in 2004, it was transferred to the ownership of the OASIS (Organization for the Advancement of Structured Information Standards) consortium. The standard's current version, as of the knowledge cutoff in September 2021, is PKCS #11 v2.40.

Hardware Security Modules (HSMs) have a separate but parallel history to PKCS #11. HSMs are devices designed to safeguard cryptographic keys and perform cryptographic operations securely. They offer tamper-resistant protection and are used in various industries to ensure sensitive data's confidentiality, integrity, and authenticity. As the demand for robust security solutions increased, integrating PKCS #11 with HSMs became a natural choice. The collaboration between PKCS #11 and HSMs allowed organizations to leverage the standardized API for interacting with cryptographic tokens while utilizing the added security benefits of dedicated hardware protection offered by HSMs.

Integrating PKCS #11 with HSMs has proven invaluable for a wide range of applications, including digital signatures, SSL/TLS (Secure Sockets Layer/Transport Layer Security) acceleration, data encryption, and key management. This combination protects sensitive cryptographic material and enhances the overall security posture of systems and applications. PKCS #11 has a long-standing history in the realm of cryptographic standards, evolving to meet the changing landscape of security needs. Integrating PKCS #11 with Hardware Security Modules (HSMs) has significantly enhanced the security and reliability of cryptographic operations, making it a vital component in modern cybersecurity practices.



# Cryptoki Application Interface (API)



Prereqs

    - Have the latest version of Python (python3)
    - Download the necessary Python modules
     -Run pip install python and pip install python-pkcs11
    - Enable the following variables on your /opt/nfast/cknfastrc file
        CKNFAST_FAKE_ACCELERATOR_LOGIN = 1
        CKNFAST_LOADSHARING = 1
        CKNFAST_DEBUG=10
        CKNFAST_DEBUGFILE= /opt/nfast/pkcs11.log
        CKNFAST_OVERRIDE_SECURITY_ASSURANCES=all 
           * Enable PKCS#11 Debug logs only if troubleshooting or if you want to see the interaction between the HSM and API.
            The directory for the debug file is arbitrary; place it where your heart feels like (heart) slightly smiling face.



![image](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/bdf4b941-08eb-4bb5-8847-57d5f24c5d73)


Introduction

The PKCS #11 (Public-Key Cryptography Standards #11) API, also known as Cryptoki (short for "Cryptographic Token Interface"), is a widely used standard that defines a platform-independent API for accessing cryptographic tokens such as hardware security modules (HSMs) and smart cards. The main goal of the PKCS #11 API is to provide a standardized interface for applications to perform cryptographic operations using these tokens while abstracting the underlying hardware details.

Key goals and features of the PKCS #11 API include:

Abstraction of Cryptographic Tokens: The API abstracts the specific details of various cryptographic tokens, allowing applications to interact with them using a consistent interface regardless of the token's physical or logical characteristics.

Security: PKCS #11 aims to provide a secure means of utilizing cryptographic functions by separating the application from the low-level cryptographic operations. It allows applications to offload cryptographic processing to dedicated hardware, which can be more resistant to certain types of attacks.

Interoperability: PKCS #11 promotes interoperability by providing a standard API that can be implemented by various vendors, ensuring that applications developed to the PKCS #11 standard can work with different hardware tokens without significant modifications.

Functionality: The API covers a broad range of cryptographic functions, including encryption, decryption, digital signatures, key generation, key management, and more. This enables developers to build secure applications that leverage these functionalities.

Cryptographic Agility: PKCS #11 allows for the dynamic loading and management of cryptographic algorithms and mechanisms, which helps ensure that applications can adapt to new security requirements and advances in cryptography over time.

Hardware Protection: Using PKCS #11 to interact with hardware tokens like HSMs, sensitive cryptographic material can be securely stored and managed within the hardware, reducing the risk of exposure and unauthorized access.

Vendor Independence: Applications that use the PKCS #11 API are not tied to a specific hardware vendor, allowing developers to choose the most suitable hardware token for their needs without being locked into a particular vendor's solution.


Process

Using the PKCS #11 API involves several steps that an application follows to interact with cryptographic tokens (such as hardware security modules or smart cards) and perform various cryptographic operations.

Here's a general overview of the typical process:

    1.Initialization:
        Load the PKCS #11 library provided by the token vendor.
        Initialize the library by calling the C_Initialize function. This sets up the PKCS #11 environment and prepares the application for interacting with cryptographic tokens.

    2.Token and Slot Enumeration:
        Enumerate available slots (physical or logical slots where tokens are inserted).
        Retrieve information about the tokens present in the slots using functions like C_GetSlotList, C_GetTokenInfo, etc.

    3.Token Management:
        Perform token-specific actions like logging in, logging out, changing PINs, etc.
        Manage cryptographic objects (keys, certificates) stored on the token using functions like C_CreateObject, C_DestroyObject, etc.

    4.Key Generation:
        Generate cryptographic keys using functions like C_GenerateKeyPair, C_GenerateKey, etc.

    5.Cryptographic Operations:
        Perform cryptographic operations like encryption, decryption, signing, and verification using the keys stored on the token.
        Use functions such as C_Encrypt, C_Decrypt, C_Sign, C_Verify, etc.

    6.Object Management:
        Manage cryptographic objects on the token, including creating, deleting, and retrieving objects using functions like C_CreateObject, C_DestroyObject, C_FindObjects, etc.

    7.Token Information:
        Retrieve information about the token, such as manufacturer details, model, serial number, supported mechanisms, etc., using functions like C_GetTokenInfo.

    8.Finalization:
        Terminate the PKCS #11 library usage by calling the C_Finalize function. This releases any resources and cleans up the PKCS #11 environment.


Advanced Encryption Standard (AES) Key Generator Script (aeskeygen.py)

Generates keys.
1. Can add custom boolean attributes to a key. 
2. Available attributes: TRUSTED, PRIVATE, PRIVATE, MODIFIABLE, SENSITIVE, EXTRACTABLE, WRAP_WITH_TRUSTED, ENCRYPT, DECRYPT, WRAP, UNWRAP, SIGN, and VERIFY. 
3. Available value pairs:  { True, yes, y, 1}  {False, no, n, 0}

Usage:
![image-2024-2-9_18-33-32](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/ae453d72-774e-4a72-80aa-22f1d4d06f31)


1. Create a key 

aeskeygen.py --generate --token-label 'loadshared accelerator' --pin 1234 --label new_key-22 --key-size 256 (verbose)

aeskeygen.py -g -t 'loadshared accelerator' -p 1234 -l new_key 22 -k 256 (short-argument)

Output:

![image-2024-2-7_8-6-31](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/96a83bfb-aa74-40cf-a096-5a366d03cbe5)


   AES Key Size Reference:

128-bit AES key /8 = 16 bytes

192-bit AES key /8 = 24 bytes

256-bit AES key /8 = 32 bytes. 


1a. Custom Key Attributes

aeskeygen.py -g -t 'loadshared accelerator' -l new_key_1234 -k 256 -a WRAP_WITH_TRUSTED=false ENCRYPT=no WRAP=n SIGN=y

![Capture](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/022b74a8-c7b5-421e-97d3-dd822b945646)


2. Delete a key

aeskeygen.py --delete --label my_key --token-label 'loadshared accelerator'  (verbose)

aeskeygen.py -d -l my_key t 'loadshared accelerator' (short-argument)

Output:

![image-2024-2-7_7-31-23](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/b39b56af-bf21-42d3-9aa9-a5fa7c6a3b8f)

3. Finds Tokens

aeskeygen.py --find-token --token-label 'loadshared accelerator' 

aeskeygen.py -f -t 'loadshared accelerator' 

Output:
![image-2024-2-6_23-1-14](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/5531c06a-982f-4a63-a848-baf529e4ddd4)


4. Find Slots 

aeskeygen.py --find-slots (verbose)

aeskeygen.py -s  (short-argument)


Output:

![image-2024-2-7_7-34-54](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/695152ad-3c17-42ae-9b71-b5246284960a)










