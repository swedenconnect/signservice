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
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSigner;
import se.swedenconnect.signservice.signature.signhandler.crypto.PSSPadding;
import se.swedenconnect.signservice.signature.signhandler.crypto.PkCrypto;
import se.swedenconnect.signservice.signature.signhandler.TestAlgorithms;
import se.swedenconnect.signservice.signature.signhandler.TestCredentials;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
class SignServiceRSAPSSSignerTest {

  static byte[] tbsData;
  static byte[] signature;
  static X509Certificate signerCert;
  static SignatureAlgorithm rsaPssSha256;
  static SignatureAlgorithm rsaPssSha384;
  static SignatureAlgorithm rsaPssSha512;

  @BeforeAll
  static void init() throws Exception {

    tbsData = Base64.decode("PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpDYW5vbmljYWxp"
      + "emF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q+P"
      + "GRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDcvMDUveG1sZHNpZy1tb3JlI3NoYTI1Ni1yc2EtTUdGMSI+PC9kczpTaW"
      + "duYXR1cmVNZXRob2Q+PGRzOlJlZmVyZW5jZSBVUkk9IiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzI"
      + "wMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcv"
      + "MjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMTk5OS9SRUMte"
      + "HBhdGgtMTk5OTExMTYiPgo8ZHM6WFBhdGg+bm90KGFuY2VzdG9yLW9yLXNlbGY6OipbbG9jYWwtbmFtZSgpPSdTaWduYXR1cmUnIGFuZCBuYW1lc3BhY2UtdXJpKC"
      + "k9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMnXSk8L2RzOlhQYXRoPgo8L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1"
      + "ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2VzdFZhbHVlPjkw"
      + "N3dxZ0VBOFVSZEx2ZE9JeWloQTQxdlJ3UlNRYWZNd3ovUk42N2xZQ0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+");

    signature = Base64.decode("TApoUVzCoMf9uhF6rY6DXKWz9NpGeOM6FVNIovT5jnZXFXQkJ6LyTloEkFU8a1cw0KZBIhTzTq25IVlSDhVlxwSF7iPL1vudj"
      + "XMWXq1+FyHsfvacTZnSWhwSSrdOtXCCN1fU8yl0qe9LiXx2vLwhroBFHwjb9tOO2+uNIpvCXndEvChHPIW1BYKHicp+u2VEhgWi8DSGJ1Arb41laPT5oFT+8Jnzhr"
      + "MKbfgae/qYSywogRP1Nnp8VN07ND4aFyn9Z8kV0qPhZklNJ8c9eRKH6jBJ+/UU9+IKhP/EvmQX6DA8uZYjJgcrRGch7+jMZ/jflOeew2y4Znhw1xTRz+rgcA==");

    byte[] certBytes = Base64.decode("MIIKzzCCCTegAwIBAgIQJfut41wXYzMb4PO2PyZ5cDANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMCU0UxFjAUBg"
      + "NVBAoTDVN3ZWRlbkNvbm5lY3QxGDAWBgNVBAsTD1NpZ25pbmcgU2VydmljZTEVMBMGA1UEBRMMc2Mtb3JnTnVtYmVyMS8wLQYDVQQDEyZDQTAwMSBTd2VkZW4gQ2"
      + "9ubmVjdCBURVNUIFNpZ24gU2VydmljZTAeFw0yMjA1MDYwOTAzMzdaFw0yMzA1MDYwOTAzMzdaMFwxFTATBgNVBAUTDDE5NTIwNzMwNjg4NjELMAkGA1UEBhMCU0"
      + "UxDzANBgNVBCoTBk1hamxpczEOMAwGA1UEBBMFTWVkaW4xFTATBgNVBAMTDE1hamxpcyBNZWRpbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJYeEU"
      + "HQncZxLqtGlksXES9owkzzZsMQ+y6XCzXemxn/Arss5wHcu2Gg2YG4RIo8Ze81XwwDc3UOr+bI1fnWFTZbDMbzJXfjhes1v/FvSCl8xiwDnB2QQLpX+eojUQH41"
      + "WxIrg9FNYjrKt9IJp7NhIipNGaKeWQ5BEv3JMnZFBN5ML9vWnOQC9C6no2qTe1iGUwYNNViXGT0qtX4IMWH3LTdvd+Vs2jxelwuV+7PFsTG0Fwm1iFhLeafAO/h"
      + "T0ajXATm8AnpyHkOhHd02h6UcdJZVEYR+yKyDIRmwKl+lETurst+6ovZKpKmq3yP63A6vTmH1LtABOJUzzTW+D/ms1sCAwEAAaOCBt8wggbbMAsGA1UdDwQEAwI"
      + "GQDAdBgNVHQ4EFgQUe000DIIE+5ONDZG3OH1+QCB8RXswEwYDVR0gBAwwCjAIBgYEAIswAQEwYQYDVR0fBFowWDBWoFSgUoZQaHR0cHM6Ly9zaWcuc2FuZGJveC"
      + "5zd2VkZW5jb25uZWN0LnNlL3NpZ3NlcnZpY2UvcHVibGlzaC9jcmwvNWU3MTI2OTZhYWNhOTBlMC5jcmwwggYHBgcqhXCBSQUBBIIF+jCCBfYwggXyDCtodHRwO"
      + "i8vaWQuZWxlZ25hbW5kZW4uc2UvYXV0aC1jb250LzEuMC9zYWNpDIIFwTxzYWNpOlNBTUxBdXRoQ29udGV4dCB4bWxuczpzYWNpPSJodHRwOi8vaWQuZWxlZ25h"
      + "bW5kZW4uc2UvYXV0aC1jb250LzEuMC9zYWNpIj48c2FjaTpBdXRoQ29udGV4dEluZm8gSWRlbnRpdHlQcm92aWRlcj0iaHR0cDovL2Rldi50ZXN0LnN3ZWRlbmNv"
      + "bm5lY3Quc2UvaWRwIiBBdXRoZW50aWNhdGlvbkluc3RhbnQ9IjIwMjItMDUtMDZUMDk6MTM6MzYuMDAwWiIgU2VydmljZUlEPSJTaWduYXR1cmUgU2VydmljZSI"
      + "gQXV0aG5Db250ZXh0Q2xhc3NSZWY9Imh0dHA6Ly9pZC5lbGVnbmFtbmRlbi5zZS9sb2EvMS4wL2xvYTMiIEFzc2VydGlvblJlZj0iXzllYmUyNzZjM2NjODMwZGV"
      + "iMjJiZTU4MmI3YTMzMzcyIi8+PHNhY2k6SWRBdHRyaWJ1dGVzPjxzYWNpOkF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjUiPjxzYW1sOk"
      + "F0dHJpYnV0ZSBGcmllbmRseU5hbWU9IlN3ZWRpc2ggUGVyc29ubnVtbWVyIiBOYW1lPSJ1cm46b2lkOjEuMi43NTIuMjkuNC4xMyIgeG1sbnM6c2FtbD0idXJuO"
      + "m9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWU+MTk1MjA3MzA2ODg2PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwv"
      + "c2FtbDpBdHRyaWJ1dGU+PC9zYWNpOkF0dHJpYnV0ZU1hcHBpbmc+PHNhY2k6QXR0cmlidXRlTWFwcGluZyBUeXBlPSJyZG4iIFJlZj0iMi41LjQuNDIiPjxzYW1"
      + "sOkF0dHJpYnV0ZSBGcmllbmRseU5hbWU9IkdpdmVuIE5hbWUiIE5hbWU9InVybjpvaWQ6Mi41LjQuNDIiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0Yz"
      + "pTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sOkF0dHJpYnV0ZVZhbHVlPk1hamxpczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FjaT"
      + "pBdHRyaWJ1dGVNYXBwaW5nPjxzYWNpOkF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjQiPjxzYW1sOkF0dHJpYnV0ZSBGcmllbmRseU5hb"
      + "WU9IlN1cm5hbWUiIE5hbWU9InVybjpvaWQ6Mi41LjQuNCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6"
      + "QXR0cmlidXRlVmFsdWU+TWVkaW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhY2k6QXR0cmlidXRlTWFwcGluZz48c2FjaTpBdHR"
      + "yaWJ1dGVNYXBwaW5nIFR5cGU9InJkbiIgUmVmPSIyLjUuNC4zIj48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJEaXNwbGF5IE5hbWUiIE5hbWU9InVybjp"
      + "vaWQ6Mi4xNi44NDAuMS4xMTM3MzAuMy4xLjI0MSIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWw6QXR0cm"
      + "lidXRlVmFsdWU+TWFqbGlzIE1lZGluPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYWNpOkF0dHJpYnV0ZU1hcHBpbmc+PC9zYWNpO"
      + "klkQXR0cmlidXRlcz48L3NhY2k6U0FNTEF1dGhDb250ZXh0PjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFJS8I2GY28rjvmWeBzgpXxWelwiWMA0GCSqGSIb3DQEB"
      + "CwUAA4IBgQAlX6fWEBVWmq5e4px3ICfk99Q+2zDFHDKct8dXh1ykc8kNjdEtgj/WuItzUJgf3apg7MPn+5sJ1OGAAHrgZBqzCQnRN5xbuDgg38PqmShwjh4Ii9O"
      + "uEmv2AXobt1ks3hCDNYLpjeTwEGBSwlEhHCbfeggxrqxIxlVMFW9eQRUAgVzu9mDUWT6dsRRojqYzEflFDJxPvxp+IEnp/X3wJlih/A4u3fx0crkg0f6RxrGRqB"
      + "lnf7APwqlLOsqD2jGu/gGiTKAzlWbSI2ET7H0DWO+mCNFxwlSBVMqLKVrBR642VrWhyjRsY3iItunK24gSeX+wRE2UR8NHBjnh3NRDbLp+bi+nagEuCksIyiY/c"
      + "Mmodnlswvu9dueBqcHUYG7ObV4v/9zC22PdtBywmJ5W37JIZuxB/mqJw/9+JhzJFqhiQqQTV1F3qMd1sDDj3ve/60CmQOPHOjyeKYOH2jwEfmyIgWrCf0Q49r2B"
      + "/y69a5M6ExG39iDrRBbw/CIQ+KHSOWs=");

    signerCert = CertificateUtils.decodeCertificate(certBytes);

    rsaPssSha256 = TestAlgorithms.getRsaPssSha256();
    rsaPssSha384 = TestAlgorithms.getRsaPssSha384();
    rsaPssSha512 = TestAlgorithms.getRsaPssSha512();


  }

  @Test
  void signRsaPss() throws Exception {
    signRsaPssWithAlgo(rsaPssSha256);
    signRsaPssWithAlgo(rsaPssSha384);
    signRsaPssWithAlgo(rsaPssSha512);
  }

  @Test
  void errorTests() throws Exception {
    log.info("RSA PSS signer error tests");

    log.info("Error test null private key:");
    specificErrorTest(tbsData, null, rsaPssSha256);
    log.info("Error test ecdsa algorithm:");
    specificErrorTest(tbsData, TestCredentials.privateRSAKey, TestAlgorithms.ecdsaSha256);
    log.info("Error test plain rsa algorithm:");
    specificErrorTest(tbsData, TestCredentials.privateRSAKey, TestAlgorithms.rsaSha256);
    log.info("Error test ecdsa key:");
    specificErrorTest(tbsData, TestCredentials.privateECKey, rsaPssSha256);
    log.info("Error test null data:");
    specificErrorTest(null, TestCredentials.privateRSAKey, rsaPssSha256);
  }

  void specificErrorTest(byte[] tbsData, PrivateKey privateKey, SignatureAlgorithm signatureAlgorithm) {
    SignServiceSigner signer = new SignServiceRSAPSSSigner();
    SignatureException signatureException = assertThrows(SignatureException.class, () -> {
      signer.sign(tbsData, privateKey, signatureAlgorithm);
    });
    log.info("Exception: {}", signatureException.toString());
  }



  void signRsaPssWithAlgo(SignatureAlgorithm signatureAlgorithm) throws Exception {
    log.info("RSA PSS Signing test using algorithm {}", signatureAlgorithm);
    SignServiceSigner signer = new SignServiceRSAPSSSigner();

    byte[] signature = signer.sign(tbsData, TestCredentials.privateRSAKey, signatureAlgorithm);
    log.info("Generated RSA PSS signature:\n{}", TestUtils.base64Print(signature, 72));

    byte[] pssPaddingBytes = PkCrypto.rsaVerifyEncodedMessage(signature, TestCredentials.publicRSAKey);
    log.info("Decrypted PSS padding:\n{}", TestUtils.base64Print(pssPaddingBytes, 72));

    Digest messageDigestFunction = DigestFactory.getDigest(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    int modLen = ((RSAKey) TestCredentials.privateRSAKey).getModulus().bitLength();
    PSSPadding pssPadding = new PSSPadding(modLen, messageDigestFunction);
    pssPadding.update(tbsData);
    boolean verifiesTbsData = pssPadding.verifySignatureEncodedMessage(pssPaddingBytes);

    assertTrue(verifiesTbsData);
    log.info("Decrypted PSS padding verifies the signed message");
  }

  @Test
  void signatureVerificationTest() throws Exception {
    log.info("Verifying externally signed RSA-PSS signature");

    log.info("Performing raw RSA decryption on external signature:\n{}", TestUtils.base64Print(signature, 72));

    byte[] pssPaddingBytes = PkCrypto.rsaVerifyEncodedMessage(signature, signerCert.getPublicKey());
    log.info("Decrypted PSS padding:\n{}", TestUtils.base64Print(pssPaddingBytes, 72));

    Digest messageDigestFunction = DigestFactory.getDigest(TestAlgorithms.rsaPssSha256.getMessageDigestAlgorithm().getJcaName());
    PSSPadding pssPadding = new PSSPadding(2048, messageDigestFunction);
    pssPadding.update(tbsData);
    boolean verifiesTbsData = pssPadding.verifySignatureEncodedMessage(pssPaddingBytes);

    assertTrue(verifiesTbsData);
    log.info("Decrypted PSS padding verifies the signed message");

  }


}