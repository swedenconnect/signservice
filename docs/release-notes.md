![Logo](images/sweden-connect.png)

# Signature Service - Release Notes

## 1.2.0

**Date:** 2025-05-23

### New and improved credentials handling

The way credentials is used and configured has been improved. See https://docs.swedenconnect.se/credentials-support.

### Updated dependencies

All underlying dependencies were updated to their latest versions.

### Bugfix for publishing SAML metadata

- See https://github.com/swedenconnect/signservice/issues/189

## 1.1.3

**Date:** 2025-01-20

### Updated dependencies

All underlying dependencies were updated to their latest versions.

## 1.1.2

**Date:** 2024-12-19

### Upgrades according to newest versions of Specifications

The new [Sweden Connect Technical Specifications](https://docs.swedenconnect.se/technical-framework/december-2024/index.html) are now supported. The following changes were made:

- In section 3.1., "Element SignRequestExtension", of [DSS Extension for Federated Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html), version 1.5, the requirements for `NotBefore` and `NotOnOrAfter` to be present under the <saml:Conditions> element was removed. The reason for this is that it will always be the SignService itself that determines whether a message has expired or not. This has been implemented.

- Section 2.2.2, "Sign Response Status Information", of [Implementation Profile for using OASIS DSS in Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/07_-_Implementation_Profile_for_using_DSS_in_Central_Signing_Services.html), version 1.6, defines two new DSS status codes; `http://id.swedenconnect.se/sig-status/1.1/authn-failed` and `http://id.swedenconnect.se/sig-status/1.1/security-violation`. Support for these codes have been added.

### Updated dependencies

All underlying dependencies were updated to their latest versions.

-----

Copyright &copy; 2022-2025, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
