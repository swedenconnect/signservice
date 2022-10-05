![Logo](../docs/images/sweden-connect.png)

# CA Repository - Design considerations

## Background and requirements

The signature service generates a new key and a new certificate for the signer at each instance of signing. This architecture has many advantages as it allows the sign service be generic and release the signature service from having to store and manage keys of signer's, it avoids the need for static certificates with fixed certificate content and it removes the need to revoke certificates caused by lost or compromised keys.

On the other hand it requires the signature service to issue may certificates.

This document adress the need to manage storage of certificates on the CA service designed to support a signature service and how this affects the API between the CA and the signature service.

## Requirements

Signature services generating new keys and issuing new certificates at each instance of signing has been in production for many years in Sweden. From these experiances we can derive the following requirements:

- Large volumes must be supported. This includes quantities up to millions of certificates every month.
- Revocation is almost non existent. Quantities in the range of 100 million certificates has been issued without a single revocation event. Revocation must be possible, but a solution for revocation does not need to be optimized to handle frequent revocation request. A high degree of manual procedures is acceptable.
- In the event of an audit, it must be possible to find a certificate from the repository based on information about the identity of the signer and the time of signing. Such events are considered rare and it is acceptable if retrieval of such certificate requires manual procedures, or even in the extreme cases, software development.
- The process to issue a certificate, which includes updating the certificate repository, must be possible within a fraction of a second. This means that at least writing of a new certificate to the CA repository must be fast and must avoid resource intence processes.
- The CA must be able to be provided as a separate service operated at a separate site by a separate entity. The requirements above must be possible even if CA is issued using an on-line protocol. For this document that protocol is assumed to be CMC using only standard features defined by RFC 5272

## Architectural design

### CMC API

The CMC protocol provides the means to issue certificates and to revoke certificates as well as functions to get certificates from the CA Respository.

The CA service dimplemented using Open Source from Sweden Connect also provides other features over CMC such as the ability to selectively retrieve a sorted section of the CA repository and other useful CA administration tasks.

From the perspective of the CA service it is howevere considered desirable if the regular signing tasks only utilizes standard CMC as it increas the chance that a standard, of-the-shelf, CA could be utilized.

For normal signing oprations only one CMC operation is required with the purpose to issue certifictes. There are no other operations the signing service is involved with as it will never take actions to revoke certificates or to retrieve existing certificates from the CA repository. Any such operation will be done at the CA istelf or using another RA service.

When issuing the certificate the signing service acts as an RA for the CA and in its role as RA it will also generate the key of the certificate subject (the signer). As the RA has posession of the private key of the signer, it is advisable to use a PKCS#10 request as the certificate request body of the CMC request. CMC also supports CRMF but this solution has a more complex solution for private key POP (proof-of-posession) and it is far less implemented.

The design choice is therefore that the CMC client of the signature service will only support one CMC request for issuing certificates based on the use of PKCS#10

### Certificate storage

#### Database usage

Some services on the market use database as storage solution for issued certificates. Experiences has however revealed some significate issues with data base useage as it tends to become the performance bottleneck for high voumes of certificates.

If a service issues one million certificates every month and these certificates are valid for a year, then there need to be on average 12 million certificates in the database. Experience show that even the simple event of adding new certificates can be a challenge given the time within which the CA has to receive, execute and deliver a certificate during a signing operation.

Another challenge is that data retention requirements often by far exceeds the time the certificate is valid. If the certificate must be stored for a longer time than it is valid, then questions arise whether the certificate should remain on the database or moved to a secondary storage. This then leads to chalenges to make sure that transfer of certificate from database to secondary storage is done without loose of sync where certificates could be lost or multiplied.

These issued becomes even more challenging if the database is replicated

Finally there is the issue related to the fact that certificate contains personal data and must be protected against loss or integrity violations.

In summary, experience has shown that the use of database as storage solution is very challengeing and sub-optimal for the persent use-case.

#### Certificate retrieval requirements

Certificates may need to be retireved as part of an audit that may be initiated by a criminal investigation. The input to such retrieval effort is never the serial number of the certificate as is the main feature of typical CA mangement APIs and protocols. In general, if someone has access to the certificate serial number, they typically has access also the the certificate itself.

Experience has shown that the need to find a certificate is based on the identity of the signer and a time when the signature was made.

Retrieval of certificates is in some CA designs required when processing a revocation request. The general idea behind this is that revocation request is done based on certificate serial number and that it is generally considered bad to accept a request to revoke a certificate without assuring that this certificxate was ever issued.

For signature services however, the situation is different. First and most importantly, revocation never happens in practice. They are merely a theoretical requirement. The theoretical case of revocation allways involves a situation where the certificate to be revoked is known, either through prosessioin of the signed document or by the process described above.

A solution for signature service does thus not need any process by which a certificate can be found effectively based on its serial number.

#### Selected solution for certificate repository storage

Based on exisitng experiences and the requirements above, the selected design for certificate storage is therefore a solution based on incremental file storage as follows:

- Certificates are stored sequentially in files
- A new file is created for each day and each file is maked with the date of storage
- Certificate files may be encrypted. The current file being written to may be exempt from encryption until the next day.
- Data replication is out of scope and can be handled separately by independent components and infrastructure.
- Traversal and retrieval of certificates is handled by a separate process separate from the signing service.
- Revocation is handled by a separate process separate from the signing servcie.
- The CMC API of the CA for remote functions by RA is restricted to functions that do not require any certificate retrieval or acess to staticstics or certificate count.
