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
package se.swedenconnect.signservice.signature.signhandler.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSigner;
import se.swedenconnect.signservice.signature.signhandler.crypto.EcdsaSigValue;
import se.swedenconnect.signservice.signature.signhandler.crypto.PkCrypto;
import se.swedenconnect.signservice.signature.testutils.TestAlgorithms;
import se.swedenconnect.signservice.signature.testutils.TestCredentials;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ECDSA signer
 */
@Slf4j
class SignServiceECSignerTest {

  static byte[] tbsData;
  static byte[] signature;
  static X509Certificate signerCert;
  static SignatureAlgorithm ecdsaSha256;
  static SignatureAlgorithm ecdsaSha384;
  static SignatureAlgorithm ecdsaSha512;

  @BeforeAll
  static void init() throws Exception {

    tbsData = Base64.decode("PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpDYW5vbmljYWxpem"
      + "F0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q+PGRzOl"
      + "NpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI2VjZHNhLXNoYTI1NiI+PC9kczpTaWduYXR1cmVNZX"
      + "Rob2Q+PGRzOlJlZmVyZW5jZSBVUkk9IiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZH"
      + "NpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZX"
      + "hjLWMxNG4jIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMTk5OS9SRUMteHBhdGgtMTk5OTExMTYiP"
      + "go8ZHM6WFBhdGg+bm90KGFuY2VzdG9yLW9yLXNlbGY6OipbbG9jYWwtbmFtZSgpPSdTaWduYXR1cmUnIGFuZCBuYW1lc3BhY2UtdXJpKCk9J2h0dHA6Ly93d3cudzMub"
      + "3JnLzIwMDAvMDkveG1sZHNpZyMnXSk8L2RzOlhQYXRoPgo8L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0d"
      + "HA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2VzdFZhbHVlPjkwN3dxZ0VBOFVSZEx2ZE9JeWloQTQxd"
      + "lJ3UlNRYWZNd3ovUk42N2xZQ0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+");

    signature = Base64.decode("iN04t3u5kTSfzkLMOtRXRXQLUBaSQX4HODZZ+1VODJibBBr+Ikzj2ci5rtVVpouVzeEOatDxsvXZHEgA6HeMHw==");

    byte[] certBytes = Base64.decode("MIIKBDCCCGygAwIBAgIQINAsb1T4uL80OEFBnTZ9ZTANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMCU0UxFjAUBgNVB"
      + "AoTDVN3ZWRlbkNvbm5lY3QxGDAWBgNVBAsTD1NpZ25pbmcgU2VydmljZTEVMBMGA1UEBRMMc2Mtb3JnTnVtYmVyMS8wLQYDVQQDEyZDQTAwMSBTd2VkZW4gQ29ubmVj"
      + "dCBURVNUIFNpZ24gU2VydmljZTAeFw0yMjA1MDYxMjEyNTZaFw0yMzA1MDYxMjEyNTZaMFwxFTATBgNVBAUTDDE5NTIwNzMwNjg4NjELMAkGA1UEBhMCU0UxDzANBgN"
      + "VBCoTBk1hamxpczEOMAwGA1UEBBMFTWVkaW4xFTATBgNVBAMTDE1hamxpcyBNZWRpbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIgCe9SmG8XUWWVWRZmOA0K6+bq"
      + "volR9KoTFCPAsRzxveYWzq+tjQTcVa3VXQIaphqH4T4VAIMMvXWl9KV82alejggbfMIIG2zALBgNVHQ8EBAMCBkAwHQYDVR0OBBYEFJqblQ28FGEqYyN3fAAQEFc1u0U"
      + "FMBMGA1UdIAQMMAowCAYGBACLMAEBMGEGA1UdHwRaMFgwVqBUoFKGUGh0dHBzOi8vc2lnLnNhbmRib3guc3dlZGVuY29ubmVjdC5zZS9zaWdzZXJ2aWNlL3B1Ymxpc2"
      + "gvY3JsLzVlNzEyNjk2YWFjYTkwZTAuY3JsMIIGBwYHKoVwgUkFAQSCBfowggX2MIIF8gwraHR0cDovL2lkLmVsZWduYW1uZGVuLnNlL2F1dGgtY29udC8xLjAvc2Fja"
      + "QyCBcE8c2FjaTpTQU1MQXV0aENvbnRleHQgeG1sbnM6c2FjaT0iaHR0cDovL2lkLmVsZWduYW1uZGVuLnNlL2F1dGgtY29udC8xLjAvc2FjaSI+PHNhY2k6QXV0aENv"
      + "bnRleHRJbmZvIElkZW50aXR5UHJvdmlkZXI9Imh0dHA6Ly9kZXYudGVzdC5zd2VkZW5jb25uZWN0LnNlL2lkcCIgQXV0aGVudGljYXRpb25JbnN0YW50PSIyMDIyLTA"
      + "1LTA2VDEyOjIyOjU2LjAwMFoiIFNlcnZpY2VJRD0iU2lnbmF0dXJlIFNlcnZpY2UiIEF1dGhuQ29udGV4dENsYXNzUmVmPSJodHRwOi8vaWQuZWxlZ25hbW5kZW4uc2"
      + "UvbG9hLzEuMC9sb2EzIiBBc3NlcnRpb25SZWY9Il9iNTJlZTUwMDMzNmMzZmMwNDNlMmZlNTJkOTM0NjRkOSIvPjxzYWNpOklkQXR0cmlidXRlcz48c2FjaTpBdHRyaW"
      + "J1dGVNYXBwaW5nIFR5cGU9InJkbiIgUmVmPSIyLjUuNC41Ij48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJTd2VkaXNoIFBlcnNvbm51bW1lciIgTmFtZT0idX"
      + "JuOm9pZDoxLjIuNzUyLjI5LjQuMTMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sOkF0dHJpYnV0ZVZhbHVlPj"
      + "E5NTIwNzMwNjg4Njwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FjaTpBdHRyaWJ1dGVNYXBwaW5nPjxzYWNpOkF0dHJpYnV0ZU1hcHBpbm"
      + "cgVHlwZT0icmRuIiBSZWY9IjIuNS40LjQyIj48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJHaXZlbiBOYW1lIiBOYW1lPSJ1cm46b2lkOjIuNS40LjQyIiB4bW"
      + "xuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZT5NYWpsaXM8L3NhbWw6QXR0cmlidXRlVmFsdW"
      + "U+PC9zYW1sOkF0dHJpYnV0ZT48L3NhY2k6QXR0cmlidXRlTWFwcGluZz48c2FjaTpBdHRyaWJ1dGVNYXBwaW5nIFR5cGU9InJkbiIgUmVmPSIyLjUuNC40Ij48c2FtbD"
      + "pBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJTdXJuYW1lIiBOYW1lPSJ1cm46b2lkOjIuNS40LjQiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMD"
      + "phc3NlcnRpb24iPjxzYW1sOkF0dHJpYnV0ZVZhbHVlPk1lZGluPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYWNpOkF0dHJpYnV0ZU1hcH"
      + "Bpbmc+PHNhY2k6QXR0cmlidXRlTWFwcGluZyBUeXBlPSJyZG4iIFJlZj0iMi41LjQuMyI+PHNhbWw6QXR0cmlidXRlIEZyaWVuZGx5TmFtZT0iRGlzcGxheSBOYW1lIi"
      + "BOYW1lPSJ1cm46b2lkOjIuMTYuODQwLjEuMTEzNzMwLjMuMS4yNDEiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW"
      + "1sOkF0dHJpYnV0ZVZhbHVlPk1hamxpcyBNZWRpbjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FjaTpBdHRyaWJ1dGVNYXBwaW5nPjwvc2"
      + "FjaTpJZEF0dHJpYnV0ZXM+PC9zYWNpOlNBTUxBdXRoQ29udGV4dD4wCQYDVR0TBAIwADAfBgNVHSMEGDAWgBSUvCNhmNvK475lngc4KV8VnpcIljANBgkqhkiG9w0BAQ"
      + "sFAAOCAYEAEYQ2mwgk1dUNe94SS/ufeQ1gRYe/6xN5S6+I6HPRNUEJToSmwWIhxYEHazm1SqUTspb1p0DSQgkFkE/vm2LSJDt+J5qpbyrLnoiO/1jYJIBnoVW5CZhYXh"
      + "m/XAoJc0SuHEXD9IJR18biipvDytEaJ9O0KYUZXRzSeMW99zx8eFjG36bZsRgVIvKTNgGUmqrpJjlkCnRO1qLkSwXm22sUT8y8UI2wrA44acYsgocOfObiwnWj5aRoKD"
      + "ZUtm+H6XXj+rmpLdDy0gFDyp/VYABbyCbzC+QiXqqiNX5ysm7F2tXcyy0ruf2tFLDn9FsCaFbyjwBLmu+nwk+DQDe1yNqwVs6/IF1ZKi9QUDzkR7LWiVNP4yomo80PIg"
      + "ZkgII/LmIOEK1FFb+i+rglP+Xm81DMaXMPCH+3VmYlLG67OrETYfhyheNipBqQZl/c+to3ZW6DctJquw2za2zKslD72znPS7K6UcpS9G/MbgbLXGijVHOpjES7HDLMy"
      + "+vsFUJldba3");

    signerCert = CertificateUtils.decodeCertificate(certBytes);

    ecdsaSha256 = TestAlgorithms.getEcdsaSha256();
    ecdsaSha384 = TestAlgorithms.getEcdsaSha384();
    ecdsaSha512 = TestAlgorithms.getEcdsaSha512();
  }


  @Test
  void signWithEcdsa() throws Exception {
    signWithEcdsaAlgorithm(ecdsaSha256, SignatureType.XML);
    signWithEcdsaAlgorithm(ecdsaSha384, SignatureType.XML);
    signWithEcdsaAlgorithm(ecdsaSha512, SignatureType.XML);
    signWithEcdsaAlgorithm(ecdsaSha256, SignatureType.PDF);
    signWithEcdsaAlgorithm(ecdsaSha384, SignatureType.PDF);
    signWithEcdsaAlgorithm(ecdsaSha512, SignatureType.PDF);
  }

  void signWithEcdsaAlgorithm(SignatureAlgorithm signatureAlgorithm, SignatureType signatureType) throws Exception {
    log.info("ECDSA Signing test using algorithm {}", signatureAlgorithm);
    SignServiceSigner signer = new SignServiceECSigner(signatureType);

    byte[] signature = signer.sign(tbsData, TestCredentials.privateECKey, signatureAlgorithm);
    log.info("Generated ECDSA signature:\n{}", TestUtils.base64Print(signature, 72));

    MessageDigest md = MessageDigest.getInstance(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    byte[] messageHash = md.digest(tbsData);
    log.info("Message hash {}", Hex.toHexString(messageHash));

    EcdsaSigValue ecdsaSigValue = null;
    switch (signatureType){

    case XML:
      ecdsaSigValue = EcdsaSigValue.getInstance(signature);
      break;
    case PDF:
      ecdsaSigValue = EcdsaSigValue.getInstance(new ASN1InputStream(signature));
      break;
    }
    boolean verifiedSignedData = PkCrypto.ecdsaVerifyDigest(messageHash, ecdsaSigValue, TestCredentials.publicECKey);
    assertTrue(verifiedSignedData);
    log.info("Decrypted signature verifies the signed message");
  }

  @Test
  void signatureVerificationTest() throws Exception {
    log.info("Verifying externally signed ECDSA signature");
    log.info("Performing ECDSA verification on external signature:\n{}", TestUtils.base64Print(signature, 72));
    MessageDigest md = MessageDigest.getInstance(ecdsaSha256.getMessageDigestAlgorithm().getJcaName());
    byte[] messageDigest = md.digest(tbsData);

    boolean verifiedSignedData = PkCrypto.ecdsaVerifyDigest(messageDigest, EcdsaSigValue.getInstance(signature), signerCert.getPublicKey());
    assertTrue(verifiedSignedData);
    log.info("Decrypted signature verifies the signed message");
  }
}