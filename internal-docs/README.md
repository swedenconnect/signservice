![Logo](images/sweden-connect.png)


# Signature Service Internal Documentation

> Contains documents and information that are internal to the project and not published on the Web (/docs).

## Presentations

- Presentation from project kick-off - [20220215-Kick-off.pdf](archive/20220215-Kick-off.pdf)

## Planning

The project planning is performed using Jira outside of this repository, so this repo doesn't contain any
milestones or tasks. However, the following milestones have been defined:

- Milestone 1 - Structure and design
  - Design and architechture is in place.
  - A runnable SignService application exists.
  - General code structure including build and CI is in place.
  - The "engine"-module is completed.
  - Other modules and handlers exist in default, or mocked implementations.
  
- Milestone 2 - Ready to release as open source
  - All modules and handlers are completed and tested, including CA. Ready for production.
  - Documentation such as architechtural descriptions, Javadoc and configuration documentation is ready.
  
- Milestone 3 - Deployment
  - Deployment of a SignService application according to DIGG's requirements.
  - Education
  - Supervision, PEN-testing, ...
  - Setup of an acceptance testing environment
  - Deploy- and project documentation
  

## Design Documents

* [Signature Service Design Documentation](Design.md)

## Useful packages

When implementing there are a number of useful libraries that can be used. This section lists some of them:

- ["Old" SignService Reference](https://github.com/idsec-solutions/signservice-ref) - The "old" SignService implementation. May be used for reference and during initial testing.

- [SignService Commons](https://github.com/idsec-solutions/signservice-commons) - Base packages useful when working with signatures. The repository comprises of:

  - SignService BOM - A Maven POM that defines a number of dependencies and their versions. Should be used also in the SignService project.
  
  - SignService Commons - Base functionality for working with signatures and some useful utility classes.
  
  - XML Commons - Functionality for XML signatures.
  
  - PDF Commons - Functionality for PDF signatures.
  
- [SignService Integration API](https://github.com/idsec-solutions/signservice-integration-api) - An API for a SignService integration service. This is mainly useful when writing test clients for the SignService.

- [SignService Integration Implementation](https://github.com/idsec-solutions/signservice-integration) - Implementations for the above API. 

- [HSM PKCS#11 Key and Certificate Generation](https://github.com/idsec-solutions/pkcs11-keygen) - Scripts for generating keys and certificates on a HSM using PKCS#11. May be used as a reference.

- [Schemas](https://github.com/swedenconnect/schemas) - JAXB modules for all XML schemas that are needed in the SignService. 

- [Credentials Support](https://github.com/swedenconnect/credentials-support) - A library for representing "credentials" (keys and certificates). Contains support for Java KeyStores and HSM stored credentials.

- [Algorithm Registry](https://github.com/swedenconnect/algorithm-registry) - A registry for cryptographic algorithms. Useful when setting "default" algorithms and when black-listing certain algorithms.

- OpenSAML Support Libraries - When implementing SAML authentication support OpenSAML is used. A set of extensions to OpenSAML exists:

  - [OpenSAML Security Extensions](https://github.com/swedenconnect/opensaml-security-ext) - Some security extensions to OpenSAML.
  
  - [OpenSAML Add-ons](https://github.com/swedenconnect/opensaml-addons) - Extensions to OpenSAML comprising of an abstraction for metadata handling making it easier to download and use SAML metadata, a builder pattern for some commonly used objects, such as creating SAML attribute objects, entity descriptors (metadata) or authentication requests, a framework for validation of responses and assertions and more.
  
  - [OpenSAML for the Swedish eID Framework](https://github.com/swedenconnect/opensaml-swedish-eid) - Extensions for the Swedish eID Framework including support for SAML extensions and all the attributes that are defined within the Swedish eID Framework.
  
- Certificate Authorithy (CA) - A number of repositories for CA-support exist:

  - [CA Engine](https://github.com/swedenconnect/ca-engine) - Library for an Open Source Certificate Authority.
  
  - [CA CMC](https://github.com/swedenconnect/ca-cmc) - An implementation of a CMC API for the CA engine with a narrowed scope to provide the essential functions of the CA via an open restful API.
  
  - [Generic CA Service](https://github.com/swedenconnect/ca-headless) - A repo contains the source code for the core headless CA service. The service is "headless", which means that it has no web GUI for management and cert issuance and consequently provides no login support for admin login.
  
  - And more. Check https://github.com/swedenconnect.
  

## Code Style

All developers contributing to this project should follow the [Spring Framework Code Style](https://github.com/spring-projects/spring-framework/wiki/Code-Style). Read it!

### Code Style Templates

* Eclipse: [code-style/spring-eclipse-code-style.xml](spring-eclipse-code-style.xml)
* IntelliJ: [code-style/spring-intellij-code-style.xml](spring-intellij-code-style.xml)

**Note**: For IntelliJ also make sure to set the editor in "never join already wrapped lines"-mode. See this [article](https://intellij-support.jetbrains.com/hc/en-us/community/posts/360006393539-How-to-prevent-IntelliJ-from-changing-file-formatting-if-lines-meet-hard-wrap-constraints-).

### Apache v 2.0 License Header

Include the following header in all Java files:

```
/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
```

Configure Eclipse or IntelliJ to do it automatically!
