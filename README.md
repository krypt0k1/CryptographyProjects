# AD CS and OSCP Integration using a nShield Hardware Security Module(HSM)
___________________________________________________________________________________________________________________________

# What is Active Directory and Certificate Services? 

Active Directory (AD) is a directory service developed by Microsoft that provides a centralized and hierarchical database for managing and organizing network resources. It is a core component of Windows-based networks and is primarily used for authentication, authorization, and management of users, computers, groups, and other network objects.

AD stores information in a structured format, utilizing the Lightweight Directory Access Protocol (LDAP). It offers a secure and scalable solution for managing large networks by allowing administrators to define policies, manage access controls, and distribute software and updates. AD domains are organized in a hierarchical structure, with a forest at the top level containing one or more domains.

Key features of Active Directory include:

1. Authentication and Single Sign-On: Users can log in to their computers using their AD credentials, which provides a single sign-on experience across various network resources.

 2. Authorization and Access Control: AD enables fine-grained access control to resources based on user or group memberships, helping to enforce security policies.

3. Group Policy: Administrators can define and enforce security settings, software installation, and other configurations for user and computer objects through Group Policy Objects (GPOs).

4. Domain Services: AD offers domain-wide services like DNS resolution, replication, and trust relationships between domains for seamless collaboration.

5. Directory Replication: AD provides automatic replication of directory data between domain controllers, ensuring data consistency and fault tolerance.

6. Security: AD offers robust security features, including Kerberos authentication, secure LDAP, and integration with Public Key Infrastructure (PKI) for digital signatures and encryption.

Certificate Services:

Certificate Services, part of Microsoft's Windows Server operating system, is a component that allows organizations to issue and manage digital certificates within their network. Digital certificates play a crucial role in establishing secure communication and verifying the identity of users, devices, and services in a networked environment.

Key aspects of Certificate Services include:

1. Public Key Infrastructure (PKI): Certificate Services enable the creation and management of a PKI, which includes components like certificate authorities (CAs), certificate revocation lists (CRLs), and certificates.

 2. Digital Certificates: Certificates bind public keys to specific entities (users, computers, services), providing a means to establish secure connections and authenticate identities in activities like SSL/TLS, email encryption, and code signing.

3. Certificate Lifecycle Management: Certificate Services facilitate the entire lifecycle of certificates, including issuance, renewal, revocation, and expiration.

4. Secure Communication: Certificates enable encrypted communication between clients and servers, safeguarding sensitive data from eavesdropping and tampering.

5. Code Signing: Developers can use certificates to sign their software, assuring users of its authenticity and integrity.

6. Authentication: Certificates support strong authentication methods, enhancing the security of network logins and transactions.

 Active Directory provides centralized user and resource management, while Certificate Services contribute to secure communication and authentication through the issuance and management of digital certificates. These services are fundamental to creating robust, secure, and well-managed network environments in organizations.

# Scope

The plan is to deploy a Two-Tier Hierarchy where we have a total of three hosts.

- One will serve as a Root-CA. 
- One host will serve as Standalone Online Sub-CA #1
- One host will serve as Standalone Online Sub-CA #2
  
To prevent compromise, the Root-CA will be offline and only turned online when required by the two Sub-CA. 

![image](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/69950c57-0b35-4731-8896-96507124b56a)


This AD CS deployment will utilize a Hardware Security Module to protect the private key of the Root CA and subsequent Sub-CA using module protection. 

A nShield 5c Security Module will be used as part of this lab. The Entrust nShield 5c is a hardware security module (HSM) designed to provide robust and tamper-resistant cryptographic services for sensitive data and critical applications. HSMs are specialized devices that safeguard cryptographic keys and perform cryptographic operations, ensuring the confidentiality, integrity, and authenticity of digital communications and transactions. 

The nShield Hardware Security Module device can be integrated into a wide range of systems, including cloud environments, virtualized infrastructure, and traditional data centers. Its ease of management and integration, combined with its ability to offload resource-intensive cryptographic tasks, contribute to improved performance and reduced operational risks.


 Prerequisites
 ----------------

 To configure a two-tier hierarchy Windows Server Public Key Infrastructure (PKI), you will need the following:

- Two Windows Server 2012 R2 or later servers
- A domain controller
- A web server (optional)
- 1 Host (Offline Root CA), 1 Host (Online Sub-CA), 1 Host (Online Sub-CA), 1 Host (Domain Controller). 
- All hosts must have Security World Software installed (proprietary Entrust hardserver software).
- All hosts must have the nCipher CNG and CSP wizards installed. The wizards come pre-installed by default with an installation of Security World Client Software.
- All hosts must have the same Security World (environment for HSM keys).

Procedure
--------------------

1. Install Security World Software (contact Entrust Support for a download link at nshield.support@entrust.com, requires an active contract with their HSM's)
2. Load or create your Security World.
3.   
4. Register the CNG and CSP wizards on each host.

   
![image](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/c11ddbcc-bda0-41e8-8ead-16563059b059)


Note:
Ensure you have a working module with a loaded Security World prior to running the CSP and CNG wizards.
 Resource on how to load a Security World on a nShield Module (https://nshielddocs.entrust.com)
   nShield Edge User Guide(https://nshielddocs.entrust.com/1/docs/edge-ug/13.3/User_Guide_nShield_Edge_13.3_Windows.pdf)
    - Section 7.1.4. Creating a Security World using new-world

4. Choose the type of protection you are going to use (Softcard, Module, or Operator Card Set protection); for the sake of simplicity, we will keep cards protected by the module.
5. Finish the wizard installations.


# Installing and Configuring the Certificate Authorities #

   - ![image](https://github.com/krypt0k1/CryptographyProjects/assets/111711434/d4154fab-5098-4800-8a30-d7dfdf1e6002)
  
Steps:

    Install and configure the root CA.
        On the first server, install the Active Directory Certificate Services (AD CS) role.
        Start the AD CS console and click Configuration.
        Select Install Root Certification Authority and click Next.
        Select Enterprise Root CA and click Next.
        Select Create a new private key and click Next.
        Select SHA256 as the signature algorithm and click Next.
        Enter a name for the root CA and click Next.
        Select a location for the CA database and log files and click Next.
        Review the summary of the configuration and click Install.

    Configure the subordinate issuing CA.
        On the second server, install the AD CS role.
        Start the AD CS console and click Configuration.
        Select Install Subordinate Certification Authority and click Next.
        Select Subordinate CA and click Next.
        Select Existing private key and click Next.
        Browse to the location of the root CA certificate and click Open.
        Enter a name for the subordinate issuing CA and click Next.
        Select a location for the CA database and log files and click Next.
        Review the summary of the configuration and click Install.

    Configure the subordinate issuing CA to issue certificates.
        On the subordinate issuing CA server, open the AD CS console.
        Expand Certificate Templates.
        Right-click the template for the type of certificate you want to issue and select Properties.
        On the General tab, select This CA should issue certificates based on this template.
        Click OK.

    Publish the root CA certificate to the domain.
        On the root CA server, open the AD CS console.
        Expand Certificates.
        Right-click the root CA certificate and select All Tasks > Publish.
        Select Active Directory.
        Click OK.

    (Optional) Publish the subordinate issuing CA certificate to the web.
        If you want to allow users to request certificates from the subordinate issuing CA over the web, you need to publish its certificate to a web server.
        On the subordinate issuing CA server, copy the certificate to the web server.
        On the web server, create a new virtual directory for the certificate.
        Place the certificate in the virtual directory.
        Configure the virtual directory to allow anonymous access.

    Configure clients to trust the root CA certificate.
        On each client computer, import the root CA certificate into the Trusted Root Certification Authorities store.
        You can do this by manually importing the certificate or by deploying it using Group Policy.

Once you have completed these steps, you will have a two-tier hierarchy PKI configured. You can then start issuing certificates to users and devices in your organization.

Additional notes:

    The root CA should be kept offline for security reasons.
    The subordinate issuing CA can be kept online, but it should be highly secured.
    You can have multiple subordinate issuing CAs subordinate to the root CA.
    You can use Group Policy to deploy certificates to users and devices in your organization.

Here are some additional recommendations for configuring a two-tier hierarchy PKI:

    Use a strong encryption algorithm for the root CA private key, such as RSA-4096.
    Use a hardware security module (HSM) to store the root CA private key.
    Keep the root CA private key and certificate in a secure location.
    Use a strong encryption algorithm for the subordinate issuing CA private key, such as RSA-2048.
    Keep the subordinate issuing CA private key and certificate in a secure location.
    Use a certificate revocation list (CRL) to publish revoked certificates.
    Use a delta CRL to publish changes to the CRL more frequently.
    Configure clients to check for CRL updates regularly.
    Monitor the PKI infrastructure for security threats.




