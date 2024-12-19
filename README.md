#  Cryptography Projects #

# Introduction 
______________________________________________________
In the contemporary digital landscape, where sensitive information traverses the virtual realm with unprecedented frequency, cryptography's significance in cybersecurity cannot be overstated. Cryptography, the science, and art of secure communication, forms a fundamental pillar of modern digital defense strategies. Its role extends far beyond mere data encryption; it encompasses safeguarding confidentiality, integrity, authentication, and non-repudiation, all of which are vital components of cybersecurity. Understanding cryptography is essential  to counteract the relentless cyber threats that target our interconnected world.

At its core, cryptography involves encoding information in a manner that only authorized individuals possess the means to decode. In an era characterized by soaring cybercrime rates and sophisticated hacking techniques, cryptographic protocols shield against data breaches, identity theft, and unauthorized access. Encryption algorithms convert plain text into unreadable gibberish, mitigating the risk of eavesdropping and unauthorized data interception. In the event of a breach, encrypted data remains indecipherable to malicious actors, rendering stolen information useless.

Furthermore, cryptography plays a pivotal role in ensuring data integrity. Hash functions generate fixed-size unique strings, or hashes, from data inputs. These hashes serve as digital fingerprints for files, messages, or documents, and any alteration to the original content leads to a different hash. By verifying hashes, users can ascertain whether data has been tampered with during transmission or storage, enabling the identification of unauthorized modifications.

Authentication, a cornerstone of cybersecurity, is another realm where cryptography shines. Digital signatures, a cryptographic technique, enable individuals to validate the origin and integrity of electronic documents. By applying a unique digital signature to a file, the sender attests to its authenticity, while recipients can verify the signature's validity. This process thwarts forgery and ensures that messages and documents are trustworthy and untampered.

Non-repudiation, closely linked to authentication, prevents individuals from denying their involvement in a transaction. Cryptographic mechanisms establish irrefutable evidence of communication or transaction occurrences. This is particularly crucial in legal and financial contexts, where parties must be held accountable for their actions.

The knowledge of cryptography is a linchpin of ineffective cybersecurity strategies. It forms an essential arsenal in the fight against an array of cyber threats that continuously exploit vulnerabilities in our digitally-dependent lives. A profound understanding of cryptographic principles empowers cybersecurity professionals to create robust defenses, secure communication channels, and establish digital trust. As our world becomes increasingly digitized and interconnected, the role of cryptography remains paramount in upholding the confidentiality, integrity, and authenticity of our digital transactions and interactions.


# PKCS #11 Projects # 

1 . p11-tool

   - [p11-tool](https://github.com/krypt0k1/CryptographyProjects/tree/p11-tool.py) is a program for managing a robust PKCS#11 infrastructure using HSM's and the Cryptoki API, designed for various cryptographic operations including encryption, decryption, key management, and more. It supports multiple cryptographic algorithms like AES, 3DES, DSA, and EC. The script leverages some custom modules and standard libraries to provide a comprehensive tool for cryptographic management. My project aims to facilitate secure cryptographic processes and hardware interactions. This tool integrates custom modules such as EncryptDecrypt, ManagementOperations, and SignVerify, along with standard libraries to ensure robust and secure cryptographic processes. In short, this tool serves as a valuable resource for any seeking to learn and enhance security practices in cryptographic environments.


2 . Public Key Exporter
   - [ExtractPubKey](https://github.com/krypt0k1/CryptographyProjects/blob/main/extractpubkey.py) is a tool that supports the export of Public Key for algorithm types: RSA, DSA, and EC. By exporting the public key, you can easily integrate it with other systems or applications that need to verify signatures or encrypt data meant for the owner of the private key. The public key also plays a crucial role in generating digital certificates. When an entity wants to obtain a digital certificate, they send a request to a Certificate Authority (CA). This request includes the public key, which serves as proof of identity. The CA verifies the request and issues a certificate that links the public key to the identity of the certificate holder.
     
     This certificate can be used for various applications, such as:
      * SSL/TLS encryption to protect website connections.
      * Encrypted and digitally signed emails.
      * Verification of an individual's or organization's identity in online transactions.
        
3 . Encryption & Decryption Tool 
   - [CryptOps](https://github.com/krypt0k1/CryptographyProjects/blob/main/cryptops.py) provides an all-encompassing solution for secure cryptographic operations such as encryption and decryption. Using the nShield Hardware Security Modules (HSMs) it supports various cryptographic algorithms including AES, 3DES, and RSA, the application uses the PKCS#11 standard use for secure and efficient communication with HSM to be highly configurable by command line logic, allowing users to specify information such as PKCS#11 library path, HSM token label, user pin, key label for encryption and decryption process. Key features include session management integration with HSM, extensive logging, and robust error-handling mechanisms. Designed with security and functionality in mind, this tool is ideal for anyone looking to integrate HSM-based cryptographic functionality into their security operations

4 . import_x509 
   - [import_x509](https://github.com/krypt0k1/CryptographyProjects/blob/main/import_x509.py) is a script to upload x.509 certificates onto an Entrust nShield Hardware Security Module with CKA_TRUSTED. It leverages the python-pkcs11 and asn1crypto modules to upload the certificate to the HSM with CKA_Trusted. It validates that the existing CKA_LABEL of the CKO_CERTIFICATE object does not exist in the HSM before calling C_CreateObject.
     ![image-2024-5-14_17-46-33](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/641fd8df-7e5f-4d5c-ae0e-3d532a581c0a)

5 . codesign.py 
   - [codsign](https://github.com/krypt0k1/CryptographyProjects/blob/main/codesign.py) is a simple Flask API application to use with the nShield Container Option pack. Allows containerized Python programs to access the HSM using the python-pkcs11 module via   cknfast.dll (Entrust PCKS#11 dll). Designed to sign files using a GET request (can be done with curl). 

Requesting a signature

curl -X POST -F "file=@C\Users\Administrator\sample.txt" http://localhost:5000/sign

curl -X POST -F "file=@C:\\Users\\Administrator\\sample.txt" http://192.168.156.145:5000/sign

Checking if API is online

curl -X GET http://localhost:5000/health or IP


![image-2024-11-5_18-18-27](https://github.com/user-attachments/assets/3d8e91e7-badf-4a0d-b06f-8e838d4fbecf)


