![Logo](images/sweden-connect.png)

# Signature Service Audit Logging

Audit logging is central in applications such as the Signature Service. Audit events are used for statistics, billing, monitoring and many other areas. This page documents the different
audit events that are produced by the SignService application and engines, including what is logged
for the different events.

## System Events

System events are produced by the SignService application itself and are not related to a specific
SignService client.

### System Started

**Event ID**: `audit.system.started`

**Description**: Is logged when the [SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) is instantiated and the system starts.

**Parameters**: No parameters

### Not Found

**Event ID**: `audit.system.not-found`

**Description**: Is logged when a request is received that can not be served.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `url` | The request URL that could not be served. |
| `method` | The HTTP method (GET, POST, ...). |

### Processing Error

**Event ID**: `audit.system.processing-error`

**Description**: Is logged when a request is handed over to an engine for processing, but the 
request fails and an error page is displayed to the user. This only happens with non-recoverable
errors. Otherwise an error response is sent back to the client.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `url` | The request URL of the request that led to an unrecoverable error. |
| `engine-name` | The name of the engine instance that processed the request. |
| `error-code` | The error code of the error. |
| `error-message` | The error message. |


## Client Specific Events

Client specific events are created based on the processing of a specific engine (client).

### Engine Started

**Event ID**: `audit.engine.started`

**Description**: A SignService engine serving a specific client was started.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that this engine is serving. |

### User Authentication

**Event ID**: `audit.engine.user.authn`

**Description**: Event that is logged when a user has authenticated as part of the signature process.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that requested the signature. |
| `request-id` | The unique ID of the sign request message. |
| `authn-id` | The unique ID of the authentication assertion issued by the authentication server. |
| `authn-server` | The ID of the authentication server (Identity Provider). |
| `authn-instant` | The authentication instant. |
| `authn-context-id` | The URI for the authentication context under which the authentication was made. |
| `authn-sign-`<br />`message-displayed` | A boolean telling whether a signature message was displayed during the user authentication process. |

**Note**: No information about the authenticated user is logged. In most cases this is considered to be
handling of personal data, and is sensitive. Future versions of this repository may include the 
configurable possibility to include this type of data.

### User Authentication Failure

**Event ID**: `audit.engine.user.authn-failure`

**Description**: Event that is logged when a user fails to authenticate during the signature process.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that requested the signature. |
| `request-id` | The unique ID of the sign request message. |
| `error-code` | The error code for the authentication error. |
| `error-message` | The error message. |

### Signature Operation Success

**Event ID**: `audit.engine.user.operation-success`

**Description**: Event that is logged when a user has successfully completed a signature operation.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that requested the signature. |
| `request-id` | The unique ID of the sign request message. |

### Signature Operation Failure

**Event ID**: `audit.engine.user.operation-failure`

**Description**: Event that is logged when a sign request operation fails and an error response
is sent back to the client.

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that requested the signature. |
| `request-id` | The unique ID of the sign request message. |
| `error-code` | The error code. |
| `error-message` | The error message. |

### Session Reset

**Event ID**: `audit.engine.user.session-reset`

**Description**: A "session reset" may occur when a sign request message is received when a user web session already exists and the expected message is an authentication response message. This is not treated as an error. Instead we assume that the previous session was abandoned by the user. However, we audit log this, since it may be useful in interactions with users (support).

**Parameters**:

| Parameter name | Description |
| :--- | :--- |
| `engine-name` | The name of the engine instance. |
| `client-id` | The unique ID of the SignService client that requested the signature. |
| `abandoned-request-id` | The ID of the SignRequest message that was previously processed but is now abandoned in favour for a new request message. |

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

