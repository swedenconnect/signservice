![Logo](../docs/images/sweden-connect.png)


# signservice/core

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-core/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-core)

-----

## About

A module containing core API:s and classes for the signature service. The module declares interfaces and
classes for common structures, and also declares interfaces for the different SignService handlers.

## SignService Engine and Handlers

The [Signature Service Architectural Overview](https://docs.swedenconnect.se/signservice/architechture.html)
describes the structure of a signature service, where an application comprises of one or several engines (one
per client), and where each engine is instantiated with a set of "handlers". The `signservice-core` module
declares interfaces for engines and handlers.

### SignService Engine

The [SignServiceEngine](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngine.java) interface describes the API for a specific SignService engine. It has
the following methods:

#### processRequest

`HttpRequestMessage processRequest(HttpServletRequest, HttpServletResponse httpResponse)`

The main entry point for a SignService Engine. The SignService application (the engine manager) supplies the HTTP servlet request and response object from the HTTP request that it is servicing and the engine processes it.

The internals, and the current state, of the engine will find out the type of message and process it accordingly.

Apart from processing requests, the engine may also serve resources. Examples of such resources
are status pages and authentication provider metadata. When a request being processed is a
request for a resource the method will not return a [HttpRequestMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/http/HttpRequestMessage.java), but instead
`null` and write the resource to the supplied `HttpServletResponse`. However, it will **not** commit the response.
This is the responsibility of the caller.

#### canProcess

`boolean canProcess(HttpServletRequest)`

A predicate that given a request tells whether this engine instance can process the request. This method
will always be invoked by the application (i.e., the engine manager) before `processRequest` is called.

---

### ProtocolHandler

The [ProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/ProtocolHandler.java) interface defines a handler that is responsible of parsing a
SignRequest message to the internal request format, and to produce a SignResponse message.

Each protocol supported should have its own ProtocolHandler-implementation.

The [ProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/ProtocolHandler.java) has the following methods:

#### decodeRequest

`SignRequestMessage decodeRequest(HttpServletRequest, SignServiceContext)`

Given a message (the HTTP servlet request) and the context the handler decodes the message into a
[SignRequestMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/SignRequestMessage.java) instance (which is the internal, and protocol-agnostic, representation
of a SignRequest message).

No validation of the message is performed, other than ensuring that a decode operation is possible.

#### createSignResponseMessage

`SignResponseMessage createSignResponseMessage(SignServiceContext, SignRequestMessage signRequestMessage)`

A factory method that creates a [SignResponseMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/SignResponseMessage.java) given the context and the corresponding 
request message. The [SignResponseMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/SignResponseMessage.java) is the internal, and protocol-agnostic, representation
of a SignResponse message.

Which parts of the [SignResponseMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/SignResponseMessage.java) that is populated is implementation dependent. 

The caller of the method can now populate the response message based on the current operation.

#### encodeResponse

`HttpRequestMessage encodeResponse(SignResponseMessage, SignServiceContext)`

Encodes a response message so that it can be returned to the SignService application.

---

### AuthenticationHandler

The [AuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/authn/AuthenticationHandler.java) interface defines methods that are used to authenticate the user
during the signature operation.

The handler interface supports authentication schemes that can authenticate the user "in one go" and schemes
that require that the user is directed to a remote authentication service (IdP). Therefore there are two methods
defined:

#### authenticate

`AuthenticationResultChoice authenticate(AuthnRequirements, SignMessage, SignServiceContext context)` 

Initiates authentication of the user. Depending on the authentication scheme the return result object 
may contain the authentication result (assertion) or a request to direct the user to a remote service.

It is the responsibility of `authenticate`, or `resumeAuthentication` (see below), to assert that all
requirements from the supplied [AuthnRequirements](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/msg/AuthnRequirements.java) are fulfilled. This means that 
the authentication must assert the supplied signer attributes and also check that the authentication is 
performed under an accepted authentication context.

#### resumeAuthentication

`AuthenticationResultChoice resumeAuthentication(HttpServletRequest, SignServiceContext)`

Resumes an authentication process. This method is invoked when the authentication scheme used leads
to that the user is directed to an external authentication service (IdP). When the user returns to the
client/service provider (the SignService application), the authentication process is resumed (and completed)
by invoking this method.

---

### KeyAndCertificateHandler

The [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) interface defines methods for 
generating the user signing credential, i.e., the private key and certificate.

#### checkRequirements

`void checkRequirements(SignRequestMessage, SignServiceContext)`

Verifies that the requirements put in the supplied SignRequest is correct and the handler can process the request.
If not an exception is thrown. The reason that this check exists is that the engine needs to ensure that a
current request is correct before sending the user to authenticate. The user would be grumpy if he or she
first authenticates and then getting an error message telling the operation failed. Better to detect any
potential errors at an early phase.

#### generateSigningCredential

`PkiCredential generateSigningCredential(SignRequestMessage, IdentityAssertion, SignServiceContext)`

Generates a signing (private) key and issues a signing certificate given the supplied parameters.
The identity assertion is the result from the user's authentication.

This step involves interaction with a Certificate Authority (CA) in order to issue the user's signature
certificate.

---

### SignatureHandler

The [SignatureHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/signature/SignatureHandler.java) interface defines methods for producing the actual signature.
The handler is activated when a user has authenticated and a user credential has been created.

#### sign

`CompletedSignatureTask sign(RequestedSignatureTask, PkiCredential, SignRequestMessage, SignServiceContext)`

Signs the supplied signature task with the given signing credential. This method is invoked once per requested
signature task (a SignRequest message may contain several "documents" to sign).

---

### AuditLogger

The [AuditLogger](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/audit/AuditLogger.java) interface defines methods for audit logging. Each engine will have its own instance of an
audit logger. Normally, we wish to separate audit logs for different customers (clients/engines). 

Audit logging is mainly performed from the engine implementation, but any handler can produce audit entries and
have them logged via the [AuditLoggerSingleton](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/audit/AuditLoggerSingleton.java).

<a name="configuration-of-handlers"></a>
## Configuration of Handlers

Configuring and setting up a Signature Service application requires that a huge amount of objects/beans are created.
Of course it is possible to do this "by hand" and create each handler and supply them with their respective settings.
However, this does not scale well, and in the end we would like to spin up an application just by supplying property
settings. Therefore, the `signservice-core` defines a framework for configuring SignService Handlers.

Each implementation of a handler must also define a corresponding configuration class and a factory that, based on the configuration, knows how create a handler instance.


The [HandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/config/HandlerConfiguration.java) interface defines common configuration settings. Implementing 
classes are expected to supply setters and getters for all properties that should be config-data for that specific 
type of configuration class.

The general idea is that a particular handler should always be "stand-alone", i.e., it should possible to create a
handler by manually assigning all of its required configuration data without the use of a
`HandlerConfiguration` data object. The `HandlerConfiguration` is intended to be used when SignService
handlers are configured, and created in an application from properties, or YML-files, for example using Spring Boot
or Quarkus.

Each class implementing the `HandlerConfiguration` must tell which [HandlerFactory](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/config/HandlerFactory.java) 
class that understands its settings and can be used to create a handler based on the configuration.

The [HandlerFactory](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/config/HandlerFactory.java) interface defines `create` methods that based on a specific configuration
creates a handler instance.


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).