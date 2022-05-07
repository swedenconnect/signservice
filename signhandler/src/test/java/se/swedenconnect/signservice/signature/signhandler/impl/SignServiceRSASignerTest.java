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
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSigner;
import se.swedenconnect.signservice.signature.signhandler.crypto.PKCS1V15Padding;
import se.swedenconnect.signservice.signature.signhandler.crypto.PkCrypto;
import se.swedenconnect.signservice.signature.signhandler.TestAlgorithms;
import se.swedenconnect.signservice.signature.signhandler.TestCredentials;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test RSA Signer
 */
@Slf4j
class SignServiceRSASignerTest {

  static byte[] tbsData;
  static byte[] signature;
  static X509Certificate signerCert;
  static SignatureAlgorithm rsaSha256;
  static SignatureAlgorithm rsaSha384;
  static SignatureAlgorithm rsaSha512;

  @BeforeAll
  static void init() throws Exception {

    tbsData = Base64.decode("PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpDYW5vbmljYWxpem"
      + "F0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q+PGRzOl"
      + "NpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiPjwvZHM6U2lnbmF0dXJlTWV0a"
      + "G9kPjxkczpSZWZlcmVuY2UgVVJJPSIiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRza"
      + "WcjZW52ZWxvcGVkLXNpZ25hdHVyZSI+PC9kczpUcmFuc2Zvcm0+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4"
      + "Yy1jMTRuIyI+PC9kczpUcmFuc2Zvcm0+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnL1RSLzE5OTkvUkVDLXhwYXRoLTE5OTkxMTE2Ij4"
      + "KPGRzOlhQYXRoPm5vdChhbmNlc3Rvci1vci1zZWxmOjoqW2xvY2FsLW5hbWUoKT0nU2lnbmF0dXJlJyBhbmQgbmFtZXNwYWNlLXVyaSgpPSdodHRwOi8vd3d3LnczLm"
      + "9yZy8yMDAwLzA5L3htbGRzaWcjJ10pPC9kczpYUGF0aD4KPC9kczpUcmFuc2Zvcm0+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJod"
      + "HRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiPjwvZHM6RGlnZXN0TWV0aG9kPjxkczpEaWdlc3RWYWx1ZT45MDd3cWdFQThVUmRMdmRPSXlpaEE0"
      + "MXZSd1JTUWFmTXd6L1JONjdsWUNJPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPg==");

    signature = Base64.decode("PcwB/C4xz9x3ce+nrv4n8F7daWF8IxbrGFmY8dDd1XmRwhQzt1mQjfdMeFtmD2uZvxbFtyIe/cOJZbLkez36ZMj5iuX4F8Dw0pLz"
      + "cp2T5JoiLz8oD/M9cmP6a8jX4Y2wtoaF55RYPY9hiJd0xPDgqJQALq+1i4TlK56carPNYtFG8YXe/LH4O2VLmFNzFEZievizpeYYjsL0+0MOVyQuRcserScZ+MAPZfi"
      + "toVwjfM1n5WKANEAgYSfJou9MlcmfwqAFRb6aGvcTDfo29oXfDEv8M//k3I845rsImSEWkxVwdTFEmYjGDGa14rsy3QL+yYO0ihYemSHj2Ot1IO9bWA==");

    byte[] certBytes = Base64.decode("MIIKzzCCCTegAwIBAgIQAy9wRRYfzQOP8bP9fID9UzANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMCU0UxFjAUBgN"
      + "VBAoTDVN3ZWRlbkNvbm5lY3QxGDAWBgNVBAsTD1NpZ25pbmcgU2VydmljZTEVMBMGA1UEBRMMc2Mtb3JnTnVtYmVyMS8wLQYDVQQDEyZDQTAwMSBTd2VkZW4gQ29u"
      + "bmVjdCBURVNUIFNpZ24gU2VydmljZTAeFw0yMjA1MDYxMDUzMTJaFw0yMzA1MDYxMDUzMTJaMFwxFTATBgNVBAUTDDE5NTIwNzMwNjg4NjELMAkGA1UEBhMCU0UxD"
      + "zANBgNVBCoTBk1hamxpczEOMAwGA1UEBBMFTWVkaW4xFTATBgNVBAMTDE1hamxpcyBNZWRpbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIDqi5AwDC"
      + "zWEYORbZz3t9Tq1nPhAeM7QzjnIFXRNrfdSMX92q9OicLbUzA6ZHE1tgw6wSJBPi3mLcm5ylk8fskdjxB8BhDz/wbyHd6KV99aGzN3JavRU1vr660+gpIhyEfBH0V"
      + "GZ3mWxYxFf3swBDYRJcCaVwmV/vVluScxpgJ8/sCIhtuBdl8iB+EJQqohUXcycdUps1J05beGDky0u0O6Wgaomi00A/gF5jhNRwskEQUq52Gt2KY1MaR+POJLyTlt"
      + "67KEdJTVkYeFilYMUddyEMGkmAGv64sNpVFFMmTahzdN0K/dK5ztCOVhNR3FM6JO0rHg+xYUdo/S5EaqjS0CAwEAAaOCBt8wggbbMAsGA1UdDwQEAwIGQDAdBgNVH"
      + "Q4EFgQUEdKHfsMlYN72Sj7MONakNk3lpA8wEwYDVR0gBAwwCjAIBgYEAIswAQEwYQYDVR0fBFowWDBWoFSgUoZQaHR0cHM6Ly9zaWcuc2FuZGJveC5zd2VkZW5jb2"
      + "5uZWN0LnNlL3NpZ3NlcnZpY2UvcHVibGlzaC9jcmwvNWU3MTI2OTZhYWNhOTBlMC5jcmwwggYHBgcqhXCBSQUBBIIF+jCCBfYwggXyDCtodHRwOi8vaWQuZWxlZ25"
      + "hbW5kZW4uc2UvYXV0aC1jb250LzEuMC9zYWNpDIIFwTxzYWNpOlNBTUxBdXRoQ29udGV4dCB4bWxuczpzYWNpPSJodHRwOi8vaWQuZWxlZ25hbW5kZW4uc2UvYXV0"
      + "aC1jb250LzEuMC9zYWNpIj48c2FjaTpBdXRoQ29udGV4dEluZm8gSWRlbnRpdHlQcm92aWRlcj0iaHR0cDovL2Rldi50ZXN0LnN3ZWRlbmNvbm5lY3Quc2UvaWRwI"
      + "iBBdXRoZW50aWNhdGlvbkluc3RhbnQ9IjIwMjItMDUtMDZUMTE6MDM6MTIuMDAwWiIgU2VydmljZUlEPSJTaWduYXR1cmUgU2VydmljZSIgQXV0aG5Db250ZXh0Q2"
      + "xhc3NSZWY9Imh0dHA6Ly9pZC5lbGVnbmFtbmRlbi5zZS9sb2EvMS4wL2xvYTMiIEFzc2VydGlvblJlZj0iXzEyN2FkYjQ0NjhkMTYwNzU1M2NmNTZmNzRmMzY4M2I"
      + "1Ii8+PHNhY2k6SWRBdHRyaWJ1dGVzPjxzYWNpOkF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjUiPjxzYW1sOkF0dHJpYnV0ZSBGcmllbmR"
      + "seU5hbWU9IlN3ZWRpc2ggUGVyc29ubnVtbWVyIiBOYW1lPSJ1cm46b2lkOjEuMi43NTIuMjkuNC4xMyIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNB"
      + "TUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWU+MTk1MjA3MzA2ODg2PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9z"
      + "YWNpOkF0dHJpYnV0ZU1hcHBpbmc+PHNhY2k6QXR0cmlidXRlTWFwcGluZyBUeXBlPSJyZG4iIFJlZj0iMi41LjQuNDIiPjxzYW1sOkF0dHJpYnV0ZSBGcmllbmRse"
      + "U5hbWU9IkdpdmVuIE5hbWUiIE5hbWU9InVybjpvaWQ6Mi41LjQuNDIiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPj"
      + "xzYW1sOkF0dHJpYnV0ZVZhbHVlPk1hamxpczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FjaTpBdHRyaWJ1dGVNYXBwaW5nPjxzYWN"
      + "pOkF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjQiPjxzYW1sOkF0dHJpYnV0ZSBGcmllbmRseU5hbWU9IlN1cm5hbWUiIE5hbWU9InVybjpv"
      + "aWQ6Mi41LjQuNCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWU+TWVkaW48L3Nhb"
      + "Ww6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhY2k6QXR0cmlidXRlTWFwcGluZz48c2FjaTpBdHRyaWJ1dGVNYXBwaW5nIFR5cGU9InJkbiIgUm"
      + "VmPSIyLjUuNC4zIj48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJEaXNwbGF5IE5hbWUiIE5hbWU9InVybjpvaWQ6Mi4xNi44NDAuMS4xMTM3MzAuMy4xLjI"
      + "0MSIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWU+TWFqbGlzIE1lZGluPC9zYW1s"
      + "OkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYWNpOkF0dHJpYnV0ZU1hcHBpbmc+PC9zYWNpOklkQXR0cmlidXRlcz48L3NhY2k6U0FNTEF1dGhDb"
      + "250ZXh0PjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFJS8I2GY28rjvmWeBzgpXxWelwiWMA0GCSqGSIb3DQEBCwUAA4IBgQCJcT+rlr3rD+jW3IMaAFYq1oamesqBJv"
      + "IqnmbR5akg6qtoKHVN1gZTAla5sb+0Z3aapJG01cdqqEdufCalW4BGQ2SQPFkX1/BMIRBR/4PiR9WBmG2MjCb8Tn9xG54WRfcv8+7xgt5J77ylWS83GaZsEzGmLNu"
      + "o53dfjY+xJ7iUMaqMkYVze+XqHnyCW471ulwVq7BYVJ95QqD4KXebBprKLLH6mDUIakaaJ3qQOh5IUstMzEFoZq91/Mit+sspuD9kwFa+KDhANTHw6ZlqtVZFEdR"
      + "/Ov3V1Ms8bAdwbHQEy3jMHyGD623tMc0i4QAZmKk9nTnuFHAM8VOFE6P8B2XjnkbPoUylcqnp4qsZjlZeaT3eTN9h2Vw9Z9/M5pkXW9+ddiVKhO5K2hXWwNNjXaO"
      + "wVJUDltOg/zejsjZbB9PEPXeFcTeFbxU668XKq/j3/pq3RlQrVe/vz6JoC+WRjp+LLC0Mcytlsj5t15sYQrb0kPC7SI6ipCef2r8CtCW8KiE=");

    signerCert = CertificateUtils.decodeCertificate(certBytes);

    rsaSha256 = TestAlgorithms.getRsaSha256();
    rsaSha384 = TestAlgorithms.getRsaSha384();
    rsaSha512 = TestAlgorithms.getRsaSha512();
  }


  @Test
  void signRsa() throws Exception {
    signRsaWithAlgo(rsaSha256);
    signRsaWithAlgo(rsaSha384);
    signRsaWithAlgo(rsaSha512);
  }

  @Test
  void errorTests() throws Exception {
    log.info("RSA signer error tests");

    log.info("Error test null private key:");
    specificErrorTest(tbsData, null, rsaSha256);
    log.info("Error test ecdsa algorithm:");
    specificErrorTest(tbsData, TestCredentials.privateRSAKey, TestAlgorithms.ecdsaSha256);
    log.info("Error test rsa-pss algorithm:");
    specificErrorTest(tbsData, TestCredentials.privateRSAKey, TestAlgorithms.rsaPssSha256);
    log.info("Error test ecdsa key:");
    specificErrorTest(tbsData, TestCredentials.privateECKey, rsaSha256);
    log.info("Error test null data:");
    specificErrorTest(null, TestCredentials.privateRSAKey, rsaSha256);
  }

  void specificErrorTest(byte[] tbsData, PrivateKey privateKey, SignatureAlgorithm signatureAlgorithm) {
    SignServiceSigner signer = new SignServiceRSASigner();
    SignatureException signatureException = assertThrows(SignatureException.class, () -> {
      signer.sign(tbsData, privateKey, signatureAlgorithm);
    });
    log.info("Exception: {}", signatureException.toString());
  }


  void signRsaWithAlgo(SignatureAlgorithm signatureAlgorithm) throws Exception {
    log.info("RSA Signing test using algorithm {}", signatureAlgorithm);
    SignServiceSigner signer = new SignServiceRSASigner();

    byte[] signature = signer.sign(tbsData, TestCredentials.privateRSAKey, signatureAlgorithm);
    log.info("Generated RSA signature:\n{}", TestUtils.base64Print(signature, 72));

    byte[] decryptedSignature = PkCrypto.rsaVerify(signature, TestCredentials.publicRSAKey);
    log.info("Decrypted signature:\n{}", TestUtils.base64Print(decryptedSignature, 72));

    MessageDigest md = MessageDigest.getInstance(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    byte[] messageDigest = md.digest(tbsData);

    boolean verifiedSignedData = PKCS1V15Padding.verifyMessageDigest(decryptedSignature, messageDigest, signatureAlgorithm.getMessageDigestAlgorithm());

    assertTrue(verifiedSignedData);
    log.info("Decrypted signature verifies the signed message");
  }

  @Test
  void signatureVerificationTest() throws Exception {
    log.info("Verifying externally signed RSA signature");
    log.info("Performing RSA decryption on external signature:\n{}", TestUtils.base64Print(signature, 72));
    byte[] decryptedSignature = PkCrypto.rsaVerify(signature, signerCert.getPublicKey());
    log.info("Decrypted signature:\n{}", TestUtils.base64Print(decryptedSignature, 72));
    MessageDigest md = MessageDigest.getInstance(rsaSha256.getMessageDigestAlgorithm().getJcaName());
    byte[] messageDigest = md.digest(tbsData);
    PKCS1V15Padding.verifyMessageDigest(decryptedSignature, messageDigest, rsaSha256.getMessageDigestAlgorithm());
    log.info("Decrypted signature verifies the signed message");
  }
}