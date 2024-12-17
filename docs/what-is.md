![Logo](images/sweden-connect.png)

# What is a Signature Service?

![SignServiceOverview](images/signservice-overview.png)

## Overview

A signature service is the central component in a remote signing model (also known as Federated 
Signing) as illustrated in this figure. This setup is characterized by a signature process that
involves a number of independent services and actors with distinct roles:

| Role                    | Description                                                                                                                                           |
|:------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| Signer                  | A person that is signing a document.                                                                                                                  |
| Service Provider        | The service visited by the signer where the signer reviews data to be signed and agrees to sign. This is also referred to as a "Signature Requester". |
| Signature Service       | Central component that manages the signature process and creates the signature.                                                                       |
| Identity Provider       | The eID service where the signer uses his or her eID to authenticate and agrees to sign.                                                                 |
| Certification Authority | Creates the signer's certificate that is attached to the signature based on the authentication of the signer in the signature process.                |


## Specific Characteristics of the Federated Signing Model

Traditional remote signature services store a static, and persistent, signing key for each signer
(person). Each such key is associated with a static and persistent certificate that is attached to
all signatures created by a particular signer. This paradigm requires that the signing service has a
fixed relationship with each signer and that it has means to ensure that a particular signing key
is dedicated to a particular signer.

The federated signing model (implemented by Sweden Connect Signature Service) evades this management
overhead by always generating a new key and a new signing certificate for each signature operation,
and by immediately, and permanently, destroying all knowledge about the signing key after a 
completed signature operation. 

In this type of model there is no need to have persistent user accounts for storing private 
signing keys or to have resources protecting those keys from unauthorized access. This is replaced
by a process where the signer is authenticated during each signature operation, typically using an
open federated authentication infrastructure (hence the popular name "Federated Signing").

This type of service is optimised for a model where the agreement with the signer to use
the Signature Service for signing, and where the responsibility for the signing process is 
managed by the Service Provider as a condition for using the service.

## Signing Flow

A significant advantage of the model where the signer has no fixed relationship with the
Signature Service is that the Signature Service can be made invisible to the signer and
integrated into the service provider flow of control. This creates a natural service context
where the service provider is responsible for the entire user experience of the signing process
and the Identity Provider is responsible for the authentication and commitment process. This
provides a natural and logical signature process as illustrated by the following example:

**The "signing of a tax declaration"-user experience:**

 1. The user visits the tax authority website to complete a tax declaration. When all information
 is entered and reviewed, the user chooses to sign and submit the declaration.
 
 2. The user is prompted to use his or her eID where the user examines a "sign message" related
 to this tax declaration and agrees to sign.
 
 3. The user is returned to the tax declaration service and gets a receipt and confirmation that
 the tax declaration is signed and submitted.

From the signer's perspective the Signature Service is simply a part of the Service Provider.

What actually happens is somewhat more complex, as illustrated by the image above:

 1. When the user agrees to sign, the Service Provider transfers the user to the Signature
 Service along with a "Sign Request" that holds the information necessary for the Signature 
 Service to complete the signature process.
 
 2. The Signature Service examines the request and transfers the user to the appropriate Identity
 Provider for authentication and acceptance to sign.
 
 3. The Identity Provider presents signature acceptance data and authenticates the signer.
 
 4. The Identity Provider transfers the user back to the Signature Service with proof of identity and acceptance to sign.
 
 5. The Signature Service generates a signing key and collaborates with the Certification Authority to create a signing certificate.
 
 6. The Signature Service completes the signature process and transfers the signer back to the Service Provider with signature data in a Sign Response message.
 
 7. The Service Provider assembles the signed document based on the data received from the Signature Service.

## Signature Service Integration

The protocol that specifies the Sign Request and Sign Response messages in this model is defined in
a number of  specifications published by Sweden Connect eID Framework specifications:

- [DSS Extension for Federated Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html).
 
- [Implementation Profile for using OASIS DSS in Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/07_-_Implementation_Profile_for_using_DSS_in_Central_Signing_Services.html).
 
- [Certificate Profile for Certificates Issued by Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/08_-_Certificate_Profile_for_Central_Signing_Services.html).
 
- [Signature Activation Protocol for Federated Signing](https://docs.swedenconnect.se/technical-framework/latest/13_-_Signature_Activation_Protocol.html).

To avoid the complexity of implementing these specifications, Service Providers normally use a
separate integration service as a backend service to create Sign Request and to parse Sign Response
documents in order to complete the signing process.

![Signature Service Integration](images/signservice-integration.png)

One important feature of this model is that the actual document to be signed is not part of
the sign request or response messages as the document itself is not necessary for the actual
signature process. This has a number of advantages, such as allowing signing of sensitive 
information while remaining a high level of integrity and confidentiality. But this also 
requires the actual signed document to be stored when creating the sign request
and retrieved from storage when parsing the sign response to complete the signing process. 
Different integration solutions exists that provides an integration service both as an API for 
direct integration and as a REST API provided by a separate service.

One such integration service that can provide integration support both as a Java API and 
through a RESTful service is the open source library https://github.com/idsec-solutions/signservice-integration.

## Levels of Security and Variations of Authentication Methods

The present Signature Service is adapted to serve a wide range of security levels from 
Qualified Electronic Signatures according to the EU eIDAS regulation, to lower levels of 
security based on simpler forms of authentication.

Several components of the specifications and features of the implementation are configurable 
to meet the requirements and the context within which the Signature Service is used.

Such aspects are:

 - Whether the Identity Provider must show a sign message or not, and get explicit approval for signing.
 
 - What level of assurance (LoA) the Identity Provider must use when authenticating the signer.
 
 - What certificate policy that is used to issue the signature certificate.
 
 - The level of protection of the signer's signing key.
 
 - The algorithms and key sizes used to generate signatures.

The overview above is written to illustrate features that are relevant only in a high level
security setup, such as functions to display a sign message and strict enforcement of the 
signer's commitment to sign. It is important to note that many of these processes are 
supported but not required. For example, it is possible to use a setup where the Identity 
Provider role is reduced to just authenticating the signer without showing any sign message.

The Signature Service implemented in the https://github.com/swedenconnect/signservice repository 
is intentionally modular in a way that allows multiple handlers for various forms of integrations
with authentication frameworks or external Certification Authority services.

This is further explained in the [architecture section](https://docs.swedenconnect.se/signservice/architechture.html).




-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

