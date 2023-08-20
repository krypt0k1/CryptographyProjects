#  Cryptography Projects #

# Introduction 
______________________________________________________
In the contemporary digital landscape, where sensitive information traverses the virtual realm with unprecedented frequency, cryptography's significance in cybersecurity cannot be overstated. Cryptography, the science, and art of secure communication, forms a fundamental pillar of modern digital defense strategies. Its role extends far beyond mere data encryption; it encompasses safeguarding confidentiality, integrity, authentication, and non-repudiation, all of which are vital components of cybersecurity. Understanding cryptography is essential for professionals and organizations to counteract the relentless cyber threats that target our interconnected world.

At its core, cryptography involves encoding information in a manner that only authorized individuals possess the means to decode. In an era characterized by soaring cybercrime rates and sophisticated hacking techniques, cryptographic protocols shield against data breaches, identity theft, and unauthorized access. Encryption algorithms convert plain text into unreadable gibberish, mitigating the risk of eavesdropping and unauthorized data interception. In the event of a breach, encrypted data remains indecipherable to malicious actors, rendering stolen information useless.

Furthermore, cryptography plays a pivotal role in ensuring data integrity. Hash functions generate fixed-size unique strings, or hashes, from data inputs. These hashes serve as digital fingerprints for files, messages, or documents, and any alteration to the original content leads to a different hash. By verifying hashes, users can ascertain whether data has been tampered with during transmission or storage, enabling the identification of unauthorized modifications.

Authentication, a cornerstone of cybersecurity, is another realm where cryptography shines. Digital signatures, a cryptographic technique, enable individuals to validate the origin and integrity of electronic documents. By applying a unique digital signature to a file, the sender attests to its authenticity, while recipients can verify the signature's validity. This process thwarts forgery and ensures that messages and documents are trustworthy and untampered.

Non-repudiation, closely linked to authentication, prevents individuals from denying their involvement in a transaction. Cryptographic mechanisms establish irrefutable evidence of communication or transaction occurrences. This is particularly crucial in legal and financial contexts, where parties must be held accountable for their actions.

The knowledge of cryptography is a linchpin of ineffective cybersecurity strategies. It forms an essential arsenal in the fight against an array of cyber threats that continuously exploit vulnerabilities in our digitally-dependent lives. A profound understanding of cryptographic principles empowers cybersecurity professionals to create robust defenses, secure communication channels, and establish digital trust. As our world becomes increasingly digitized and interconnected, the role of cryptography remains paramount in upholding the confidentiality, integrity, and authenticity of our digital transactions and interactions.






# Application Interface (API)
Scope


1	

Understand and comprehend nShield PKCS11 User Guide and CKNFASTRC variables.
	✔️ 	✔️
2	Review PKCS11 Token Interface Base Spec, Python PKCS11 Library, and Integration guide, 	✔️ 	✔️
3	

Define the capabilities and functions of the application:

     Initialization
     Token and Slot Enumeration
     Token Management
    Key Generation
     Cryptographic Operations
     Object Management
     Token Information
     Finalization

	

✔️
	


4	


Create an application with a GUI that communicates with the HSM via the Entrust P11 Library.
	


	



Prereqs

1. Have the latest version of Python (python3)
2. Download the pkcs11 module
3. Run pip install python and pip install python-pkcs11
4. Enable the following variables on your /opt/nfast/cknfastrc file
        CKNFAST_FAKE_ACCELERATOR_LOGIN = 1
        CKNFAST_LOADSHARING = 1
        CKNFAST_DEBUG=10
        CKNFAST_DEBUGFILE= /opt/nfast/
            The directory for the debug file is arbitrary; place it where your heart feels like (heart) slightly smiling face.

Introduction

The PKCS #11 (Public-Key Cryptography Standards #11) API, also known as Cryptoki (short for "Cryptographic Token Interface"), is a widely used standard that defines a platform-independent API for accessing cryptographic tokens such as hardware security modules (HSMs) and smart cards. The main goal of the PKCS #11 API is to provide a standardized interface for applications to perform cryptographic operations using these tokens while abstracting the underlying hardware details.

Key goals and features of the PKCS #11 API include:

1. Abstraction of Cryptographic Tokens: The API abstracts the specific details of various cryptographic tokens, allowing applications to interact with them using a consistent interface regardless of the token's physical or logical characteristics.

2. Security: PKCS #11 aims to provide a secure means of utilizing cryptographic functions by separating the application from the low-level cryptographic operations. It allows applications to offload cryptographic processing to dedicated hardware, which can be more resistant to certain types of attacks.

3. Interoperability: PKCS #11 promotes interoperability by providing a standard API that can be implemented by various vendors, ensuring that applications developed to the PKCS #11 standard can work with different hardware tokens without significant modifications.

4. Functionality: The API covers a broad range of cryptographic functions, including encryption, decryption, digital signatures, key generation, key management, and more. This enables developers to build secure applications that leverage these functionalities.

5. Cryptographic Agility: PKCS #11 allows for the dynamic loading and management of cryptographic algorithms and mechanisms, which helps ensure that applications can adapt to new security requirements and advances in cryptography over time.

6. Hardware Protection: Using PKCS #11 to interact with hardware tokens like HSMs, sensitive cryptographic material can be securely stored and managed within the hardware, reducing the risk of exposure and unauthorized access.

7. Vendor Independence: Applications that use the PKCS #11 API are not tied to a specific hardware vendor, allowing developers to choose the most suitable hardware token for their needs without being locked into a particular vendor's solution.


# Process

Using the PKCS #11 API involves several steps that an application follows to interact with cryptographic tokens (such as hardware security modules or smart cards) and perform various cryptographic operations.

Here's a general overview of the typical process:

1.  Initialization
2.  Load the PKCS #11 library provided by the token vendor.
3.  Initialize the library by calling the C_Initialize function. (This sets up the PKCS #11 environment and prepares the application for interacting with cryptographic tokens.
4.  Token and Slot Enumeration:
        Enumerate available slots (physical or logical slots where tokens are inserted).
        Retrieve information about the tokens present in the slots using functions like C_GetSlotList, C_GetTokenInfo, etc.
5.  Token Management:
        Perform token-specific actions like logging in, logging out, changing PINs, etc.
        Manage cryptographic objects (keys, certificates) stored on the token using functions like C_CreateObject, C_DestroyObject, etc.

6.  Key Generation:
        Generate cryptographic keys using functions like C_GenerateKeyPair, C_GenerateKey, etc.

7.  Cryptographic Operations:
        Perform cryptographic operations like encryption, decryption, signing, and verification using the keys stored on the token.
        Use functions such as C_Encrypt, C_Decrypt, C_Sign, C_Verify, etc.

8.  Object Management:
        Manage cryptographic objects on the token, including creating, deleting, and retrieving objects using functions like C_CreateObject, C_DestroyObject, C_FindObjects, etc.

9.    Token Information:
        Retrieve information about the token, such as manufacturer details, model, serial number, supported mechanisms, etc., using functions like C_GetTokenInfo.

10.    Finalization:
        Terminate the PKCS #11 library usage by calling the C_Finalize function. This releases any resources and cleans up the PKCS #11 environment.

It's important to note that while these steps provide a general outline of the PKCS #11 process, the actual implementation details and function names may vary based on the specific PKCS #11 library and token vendor.

Developers need to refer to the documentation provided by the vendor to understand the exact functions and parameters required for their specific use case.


Code Progress
WORK IN PROGRESS


Milestones:

1. Create GUI with functional buttons. ✔️
2. Create an organized UI for the application.
3. Tie buttons to call various functions of the Entrust PKCS #11 library.
4. Test if buttons can action the function call.
5. Debug ( OPENSC_DEBUG)
7. TBD



import tkinter as tk
from tkinter import messagebox
from tkinter import *  
from pkcs11 import *
 
 
## Define Menus
def show_about():
    messagebox.showinfo("About", "Developed by Armando Montero Property of Entrust & nCipher Security")
    
def option1_action():
    messagebox.showinfo("1."),( "Create a Session.")
 
def option2_action():
    messagebox.showinfo("2."),( "Generate keys.")
 
def option3_action():
    messagebox.showinfo("3.)"),( "Import or Export keys.")
 
def option4_action():
    messagebox.showinfo("4."), ("Create a PKCS #11 Certificate.")
 
def exit_program():
    if messagebox.askokcancel("Exit", "Do you want to exit?"):
        root.quit()
 
## Create the main application window
root = tk.Tk()
root.title("PKCS #11 Program")
 
## Create a menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)
 
 
## Create a file menu
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=exit_program)
menu_bar.add_cascade(label="File", menu=file_menu)
 
## Create a help menu
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menu_bar.add_cascade(label="Help", menu=help_menu)
 
## Create an options menu
options_menu = tk.Menu(menu_bar, tearoff=0)
options_menu.add_command(label="tbd", command=option1_action)
options_menu.add_command(label="tbd", command=option2_action)
options_menu.add_command(label="tbd", command=option3_action)
menu_bar.add_cascade(label="Options", menu=options_menu)
 
#Define PKCS #11 Functions
 
 
## Create buttons
 
 
def InitToken():
    myLabel = Label(root, text="Label: C_Initialize")
    myLabel.pack()
 
def Login():
    myLabel = Label(root, text="Label: C_Login")
    myLabel.pack()
 
def KeyGeneration():
    myLabel = Label(root, text="Label: C_GenerateKey, C_GenerateKeyPair")
    myLabel.pack()
 
 
myButton = Button(root, text="Init Token", command=InitToken)
myButton.pack()
 
myButton = Button(root, text="Login Token", command=Login)
myButton.pack()
 
myButton = Button(root, text="Generate Key", command=KeyGeneration)
myButton.pack()
 
## Run the application
root.mainloop()'''


PKCS #11 Related Functions


Initialization & Token/ Slot Enumeration.


import os
import pkcs11
from pkcs11 import *
 
 
 
## Specify the correct environment variable that contains the path to the PKCS#11 library
pkcs11_lib_path = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
 
## Load the PKCS#11 library from the specified path
lib = pkcs11.lib(pkcs11_lib_path)
 
## Get a token object from the loaded library, specifying the token label ('loadshared accelerator' in this case)
token = lib.get_token(token_label='loadshared accelerator')
 
## FYI token_label will need one of the slot names from your /opt/nfast/cklist output.
## Given that the CKNFAST_LOADSHARING = 1 variable puts all slots tokens into a singular slot, we're able to see them all pop at once.
 
## Open a session with the token, indicating that it's a read-write session and providing the user PIN ('1234' in this case) for authentication
 
## To login as Security Officer (SO) change user_pin to so_pin
 
## example:
#with token.open(rw=True, so_pin= 'asg123;') as session:
 
## Login as user
with token.open(rw=True, user_pin='1234') as session:
     print(session)
 
## Gets the slots names
 
for slot in lib.get_slots():
    token = slot.get_token()
    print(token)
 
    if token.label == '...':
        break
 
 
 
 
 
 
 
 
 
 
Output:
 
<pkcs11._pkcs11.Session object at 0x7f0fe42978d0>
 
loadshared accelerator



Ok, so we get back our session, token name, and our PKCS #11 logs confirm that the session happened.


2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetFunctionList
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    ppFunctionList 0x7fb085cff298
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_Initialize
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    voidp (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   13.4.4-379-58f7ed87
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    init_tweakflags
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Turn on loadsharing
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 Warning: Pretend accelerator slot supports login
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    PKCS#11 ECDH derive concatenate KDF X9.63 Compliant
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Elastic mode is not set
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    init_mutexes
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Single threaded (voidp NULL)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__init_context
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Setting pool mode disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFKM_getinfo
11:59:38 DEBUG1: Fetched client id for private connection
11:59:38 DEBUG1: Server supports fastpoll commands
11:59:38 DEBUG1: Read kmdata file /opt/nfast/kmdata/local/world
11:59:38 DEBUG1: Module count changed (0 to 1)
11:59:38 DEBUG1: Module #1: Submitted PollSlotList
11:59:38 DEBUG1: Module #1: Submitted PollModuleState
11:59:38 DEBUG1: Module #1: Reaped PollSlotList
11:59:38 DEBUG1: Module #1: Reaped PollModuleState
11:59:38 DEBUG1: Module #1: Rechecking module
11:59:38 DEBUG1: Module #1: Security world checks out ok
11:59:38 DEBUG1: Read kmdata file /opt/nfast/kmdata/local/module_B680-0AA9-E651
11:59:38 DEBUG1: Module #1: Submitted GetSlotInfo for slot 0
11:59:38 DEBUG1: Module #1: Reaped GetSlotInfo for slot 0
11:59:38 DEBUG1: kmdata file /opt/nfast/kmdata/local/cards_63d0ae46dd49262e0b6a4d89c7c9c85abb6a6516 does not exist
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFKM_listkeys
11:59:38 DEBUG1: scandir (prefix key, matching pkcs11) returned 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    init_security_flags
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    CKNFAST_OVERRIDE_SECURITY_ASSURANCES is unset, check with default settings
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    session_create_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__configure_sokey
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Security Officer: Initialising PKCS#11 Security Officer data
11:59:38 DEBUG1: scandir (prefix softcard, matching ANY) returned 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Security Officer: SO Token not found.
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Security Officer: Artefacts do not exist
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_real_slots, all EOs are Security Officer artefacts -- keeping with real slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_real_slots, n_modules 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 1 status 2
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 1 in KM world, 3 slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_real_slots n_realslots 4
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    fill_real_slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Found new module #1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_create_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__make_derive_acl, role 2
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__getconnection
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    make_acl_group_state_blob
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_template_key slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__make_derive_acl, role 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__getconnection
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    make_acl_group_state_blob
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_template_key slot 0x1D622495 fipshooptemplatekey 0x8329FCBF
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622495 wrapkey 0x8329FCBE template 0x8329FCBF
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_wrap_template_key slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__make_derive_acl, role 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__getconnection
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    make_acl_group_state_blob
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_wrap_template_key slot 0x1D622495 wraptemp 0x8329FCBC
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    KISAAlgorithms feature enabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    EC algorithms feature enabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_KEY_GEN in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_ECB in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_ECB_ENCRYPT_DATA in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_CBC in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_CBC_PAD in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_MAC in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_DES_MAC_GENERAL in strict FIPS level 3 mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disabled single DES mechanisms in FIPS mode
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGE_AUTS
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGE_RESYNC
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGE_OPC
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGERC_KEY_GEN
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGEOP_KEY_GEN
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_MILENAGESUBSCRIBER_KEY_GEN
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAK
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAK_AUTS
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAK_RESYNC
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAK_TOPC
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAKTOP_KEY_GEN
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disable mechanism CKM_NC_TUAKSUBSCRIBER_KEY_GEN
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Disabled 3GPP mechanisms
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    module maxwrite 262152, trim/round to 261952\x0A
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Found new realslot #1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 1 has tokens
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    fill_real_slots_tokens_physical
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 1 token type 2 real slot[1] 0x2139fc8 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_create_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622496 fipshoopwrapkey 0x8329FCBE already loaded
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_wrap_template_key slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    wrap template 0x8329fcbc already loaded
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    update_real_slot 0x1D622496 moduleinfo 0x20206f0 slotinfo 0x20970d0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    previous_ic 0, new 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    SlotState_Unidentified
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x000000E1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Found new realslot #2
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 1 token type 2 real slot[2] 0x213a230 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_create_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x1D622497 fipshoopwrapkey 0x8329FCBE already loaded
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_wrap_template_key slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    wrap template 0x8329fcbc already loaded
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    update_real_slot 0x1D622497 moduleinfo 0x20206f0 slotinfo 0x1fc8eb0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    previous_ic 0, new 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Empty, empty before
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x000000E0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Found new realslot #3
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Initialized 3 real slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_virtual_slots - NFKM_listcardsets
11:59:38 DEBUG1: scandir (prefix cards, matching ANY) returned 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_virtual_slots - NFKM_listsoftcards 
11:59:38 DEBUG1: scandir (prefix softcard, matching ANY) returned 0
11:59:38 DEBUG1: scandir (prefix softcard, matching ANY) returned 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    count_virtual_slots n_virtualslots 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    plus virtual accelerator slot
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_create_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap create size 128
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_export_hoop_keys slot 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    create_wrap_template_key slot 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Loadshared slot, skip
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    read_moduletoken_data
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Module 0 ModuleState_Usable
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    CKF_TOKEN_PRESENT
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    listkeys
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    List keys - 1 keys
11:59:38 DEBUG1: Read kmdata file /opt/nfast/kmdata/local/key_pkcs11_uaef814375c102d1d958c2161b8bfe024a9f2dbea7
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__load_nfkmkey nfkmkey 0x1ef7630
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    protected entry type 0x00020002
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Public (module-protected) versioned object, load it
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__get_real_slot module 0 key 0x00000000
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Use realslot module 1 with cardset, fipsauth (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Loaded temp keyid 0x8329fcbd
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__alloc_transact, slot_mutex_held FALSE
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Exported 0x8329fcbd
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NF_Unmarshal_CKObjectNew, len 196
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Unmarshalled object
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Secret key - real 0 considered 0 version 5
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__destroy_key 0x8329fcbd
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    new object handle 0x0000045E
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    nfkmkey_load_privblob, NFKM_Key ident uaef814375c102d1d958c2161b8bfe024a9f2dbea7
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__link_object token
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_object_handle 0x0000045E
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap insert hash 22F0A7C0237 probe 55 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Object 0x0000045E 0x2137960
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert try hashmap[55] hash 00000000 value (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert hashmap[55] value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    After insert size 128, used 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    public entry type 0x00010002
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    No unprotected object
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    We have recovery data
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__load_nfkmkey objectidenthashpriv objpriv
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_object_ident ef814375c102d1d958c2161b8bfe024a9f2dbea7 0xD9D102C1754381EF
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap insert hash D9D102C1754381EF probe 111 step 3
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Object uaef814375c102d1d958c2161b8bfe024a9f2dbea7 0x0000045E 0x2137960
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert try hashmap[111] hash 00000000 value (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert hashmap[111] value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    After insert size 128, used 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    update_real_slot 0x1D622496 moduleinfo 0x20206f0 slotinfo 0x20970d0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    previous_ic 1, new 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    SlotState_Unidentified
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x000000E1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    update_real_slot 0x1D622497 moduleinfo 0x20206f0 slotinfo 0x1fc8eb0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    previous_ic 0, new 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Empty, empty before
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x000000E0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    loadshared accelerator slot
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x00000000
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Initialized 1 virtual slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetInfo
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetSlotList
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    tokenPresent 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pSlotList (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pulCount 0x7ffd78dab4a0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Get loadsharing slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    *pulCount 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetSlotList
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    tokenPresent 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pSlotList 0x20eef50
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pulCount 0x7ffd78dab4a0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    *pulCount 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    Get loadsharing slots
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    *pulCount 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    pSlotList[0] 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetSlotInfo
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    slotID 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pInfo 0x7ffd78dab5c0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    loadshared accelerator slot
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x00000000
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    pInfo->flags 0x00000005
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetTokenInfo
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    slotID 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    loadshared accelerator slot
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__update_token_present returning 0x00000000
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    pInfo->flags 0x00000609
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetMechanismList
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    slotID 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pMechanismList (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pulCount 0x7ffd78dab5a0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    *pulCount 140396136683488
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_GetMechanismList
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    slotID 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pMechanismList 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    pulCount 0x7ffd78dab5a0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    *pulCount 177
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGERC_KEY_GEN disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGEOP_KEY_GEN disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGESUBSCRIBER_KEY_GEN disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGE disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGE_AUTS disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGE_RESYNC disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_MILENAGE_OPC disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAKTOP_KEY_GEN disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAKSUBSCRIBER_KEY_GEN disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAK disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAK_AUTS disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAK_RESYNC disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    mechanism CKM_NC_TUAK_TOPC disabled
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_OpenSession
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    slotID 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >    flags 0x00000006
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    new session handle 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap insert hash 46569E98220 probe 32 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    Session 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert try hashmap[32] hash 00000000 value (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    insert hashmap[32] value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    After insert size 128, used 1
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    *phSession 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >>   C_Login
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >    hSession 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >    userType CKU_USER
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >    ulPinLen 4
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    hashmap lookup hash 46569E98220 probe 32 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    lookup try hashmap[32] hash 46569E98220 value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    found hashmap[32] value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    slot 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB Warning: Login not supported on slot 0x2D622495, pretending it is
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    Load private objects
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    Asynchronous batch size = 100
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    NFC__fixup_nfkmkey objpriv 0x0000045E (0x203e650) objpub 0x00000000 ((nil))
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >>   C_Logout
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >    hSession 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    hashmap lookup hash 46569E98220 probe 32 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    lookup try hashmap[32] hash 46569E98220 value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    found hashmap[32] value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    logout, slot 0x2119b10
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB Warning: Login/out not supported on slot 0x2D622495, pretending it is
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >>   C_CloseSession
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB >    hSession 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    hashmap lookup hash 46569E98220 probe 32 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    lookup try hashmap[32] hash 46569E98220 value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    found hashmap[32] value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    hashmap lookup hash 46569E98220 probe 32 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    lookup try hashmap[32] hash 46569E98220 value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    found hashmap[32] value 0x21469f0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    After remove size 128, used 0
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB D    Free session 0x000008CB
2023-08-17 11:59:38 [3355128]: pkcs11: 000008CB <    rv 0x00000000 (CKR_OK)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 >>   C_Finalize
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__end_slot 0x2D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__slot_free_objects
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__free_object, objdata 0x203e650 handle 0x0000045E
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    delete_blob
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    delete_blob - it's empty
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_object_handle 0x0000045E
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap lookup hash 22F0A7C0237 probe 55 step 5
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    lookup try hashmap[55] hash 22F0A7C0237 value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    found hashmap[55] value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    After remove size 128, used 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__hash_object_ident ef814375c102d1d958c2161b8bfe024a9f2dbea7 0xD9D102C1754381EF
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    hashmap lookup hash D9D102C1754381EF probe 111 step 3
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    lookup try hashmap[111] hash D9D102C1754381EF value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__cmp_object_ident uaef814375c102d1d958c2161b8bfe024a9f2dbea7 uaef814375c102d1d958c2161b8bfe024a9f2dbea7
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    found hashmap[111] value 0x203e650
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    After remove size 128, used 0
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__unlink_object 0000045E slotID 2D622495 objdata->obj 0x2137960
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    free nfkmkey 0x1ef7630
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    freed nfkmkey (nil)
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NF_FreeCK_CKObjectNew
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps done
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop key 0x8329FCBE on slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__destroy_key 0x8329fcbe
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop template key 0x8329FCBF on slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__destroy_key 0x8329fcbf
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy wrap template key 0x8329FCBC on slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__destroy_key 0x8329fcbc
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__end_slot 0x1D622495
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__slot_free_objects
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps done
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop key 0x8329FCBE on slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop template key 0x8329FCBF on slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy wrap template key 0x8329FCBC on slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__end_slot 0x1D622496
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__slot_free_objects
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps done
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop key 0x8329FCBE on slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy fips hoop template key 0x8329FCBF on slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    destroy wrap template key 0x8329FCBC on slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__end_slot 0x1D622497
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    NFC__slot_free_objects
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 D    slot_destroy_hashmaps done
2023-08-17 11:59:38 [3355128]: pkcs11: 00000000 <    rv 0x00000000



Testing Softcard and OCS capabilities


Generating OCS protected PKCS #11 AES key
──(root㉿kali)-[/opt/nfast/bin]
 
└─# ./generatekey pkcs11                                                                                          
 
protect: Protected by? (token, module) [token] > token
 
slot: Slot to read cards from? (0-2) [0] > 
 
0recovery: Key recovery? (yes/no) [yes] > yes
 
ERROR: recovery: invalid option
 
recovery: Key recovery? (yes/no) [yes] > yes
 
type: Key type? (DES3, DH, DHEx, DSA, HMACSHA1, HMACSHA256, HMACSHA384,
 
                 HMACSHA512, RSA, DES2, AES, Rijndael, ECDSA, ECDH, Ed25519,
 
                 X25519) [RSA] > AES
 
size: Key size? (bits, 128-256) [] > 256
 
plainname: Key name? [] > OCSprot 
 
nvram: Blob in NVRAM (needs ACS)? (yes/no) [no] > no
 
key generation parameters:
 
 operation    Operation to perform       generate
 
 application  Application                pkcs11
 
 protect      Protected by               token
 
 slot         Slot to read cards from    0
 
 recovery     Key recovery               yes
 
 verify       Verify security of key     yes
 
 type         Key type                   AES
 
 size         Key size                   256
 
 plainname    Key name                   OCSprot
 
 nvram        Blob in NVRAM (needs ACS)  no
 
Loading `PKCS11OCS':
 
 Module 1: 0 cards of 1 read           
 
 Module 1 slot 0: `PKCS11OCS' #1       
 
 Module 1 slot 2: empty                
 
 Module 1 slot 0:- passphrase supplied - reading card                                                                                                                                                                                     
 
Card reading complete.             
 
                                   
 
Key successfully generated.
 
Path to key: /opt/nfast/kmdata/local/key_pkcs11_ucc6047b06b40103570ba0ae2fa39d0eb2ef5ae7e6-5f5b3122df0741e28c9361b34c9834f69cc73d43
   
                                                                                                                                                                                                                                          
┌──(root㉿kali)-[/opt/nfast/bin]
└─# ./ppmk --new -m1 --force PKCS11SoftCard
Enter new pass phrase:
Enter new pass phrase again:
New softcard created: HKLTU 96738a35471d8480f8d0aa1728d9eb8f1c6a983f


Checking slots


┌──(root㉿kali)-[/opt/nfast/bin]
└─# ./cklist
Listing contents of slot 0
 (token label "loadshared accelerator          ")
 
Passphrase:
  CKA_CLASS CKO_SECRET_KEY
  CKA_TOKEN true
  CKA_PRIVATE false
  CKA_MODIFIABLE true
  CKA_LABEL "test_key"
  CKA_NFKM_APPNAME "pkcs11"
  CKA_NFKM_ID "uaef814375c102d1d958c2161b8bfe024a9f2dbea7"
  CKA_NFKM_HASH length 20
    { C6D2E42D B78EDB91 231C8600 9E33EA9F F6401158 }
  CKA_KEY_TYPE CKK_AES
  CKA_ID length 0
  CKA_DERIVE false
  CKA_LOCAL false
  CKA_START_DATE 0000 00 00
  CKA_END_DATE 0000 00 00
  CKA_KEY_GEN_MECHANISM CK_UNAVAILABLE_INFORMATION
  CKA_ALLOWED_MECHANISMS: ANY
  CKA_SENSITIVE true
  CKA_ENCRYPT true
  CKA_DECRYPT true
  CKA_SIGN true
  CKA_VERIFY true
  CKA_WRAP true
  CKA_UNWRAP true
  CKA_EXTRACTABLE false
  CKA_ALWAYS_SENSITIVE true
  CKA_NEVER_EXTRACTABLE true
  CKA_VALUE_LEN 32
 
 
Listing contents of slot 1
 (token label "PKCS11OCS                       ")
 
Passphrase:
  CKA_CLASS CKO_SECRET_KEY
  CKA_TOKEN true
  CKA_PRIVATE true
  CKA_MODIFIABLE true
  CKA_LABEL "OCSprot"
  CKA_NFKM_APPNAME "pkcs11"
  CKA_NFKM_ID "ucc6047b06b40103570ba0ae2fa39d0eb2ef5ae7e6-5f5b3122df0741e28c9361b34c9834f69cc73d43"
  CKA_NFKM_HASH length 20
    { E2F90205 7E55B231 0A9ADB4C 372DCB2B 25EDF5E9 }
  CKA_KEY_TYPE CKK_AES
  CKA_ID length 0
  CKA_DERIVE false
  CKA_LOCAL false
  CKA_START_DATE 0000 00 00
  CKA_END_DATE 0000 00 00
  CKA_KEY_GEN_MECHANISM CK_UNAVAILABLE_INFORMATION
  CKA_ALLOWED_MECHANISMS: ANY
  CKA_SENSITIVE true
  CKA_ENCRYPT true
  CKA_DECRYPT true
  CKA_SIGN true
  CKA_VERIFY true
  CKA_WRAP true
  CKA_UNWRAP true
  CKA_EXTRACTABLE false
  CKA_ALWAYS_SENSITIVE true
  CKA_NEVER_EXTRACTABLE true
  CKA_VALUE_LEN 32


──(root㉿kali)-[/home/administrator/Documents]
 
└─# python3 python11.py  
<pkcs11._pkcs11.Session object at 0x7fdc40027fd0>
loadshared accelerator
PKCS11OCS
PKCS11SoftCard


Okay, I am able to see all my tokens

    loadshared accelerator (module prot)
    PKCS11OCS (ocs prot)
    PKCS11SoftcCard (softcard prot)


So far so good grinning face with smiling eyes; now, let's make it show us the objects within the Token.
Like
Be the first to like this



