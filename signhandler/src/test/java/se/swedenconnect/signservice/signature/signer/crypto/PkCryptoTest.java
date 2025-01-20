/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.signature.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.signature.signer.TestAlgorithms;
import se.swedenconnect.signservice.signature.signer.TestCredentials;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

/**
 * Test PK Crypto implementation
 */
@Slf4j
class PkCryptoTest {

  @Test
  void rsaSigningTest() throws Exception {
    log.info("RSA sign and verify test");
    MessageDigest md = MessageDigest.getInstance(TestAlgorithms.sha256.getJcaName());
    byte[] messageHash = md.digest("Data to be signed".getBytes(StandardCharsets.UTF_8));
    log.info("Message hash {}", Hex.toHexString(messageHash));
    byte[] tbsdr = PKCS1V15Padding.getRSAPkcs1DigestInfo(TestAlgorithms.sha256, messageHash);
    log.info("Padded hash (PKCS#1 1.5 {}", Hex.toHexString(tbsdr));
    byte[] signatureBytes = PkCrypto.rsaSign(tbsdr, TestCredentials.privateRSAKey);
    log.info("Signature bytes (RSA sign: \n{}", TestUtils.base64Print(signatureBytes, 74));
    byte[] decrypted = PkCrypto.rsaVerify(signatureBytes, TestCredentials.publicRSAKey);
    log.info("Decrypted signature value: {}", Hex.toHexString(decrypted));

    try (ASN1InputStream asn1InputStream = new ASN1InputStream(decrypted)) {
      ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());
      ASN1OctetString octetString = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));

      assertArrayEquals(messageHash, octetString.getOctets());
      log.info("Decrypted value match");

      byte[] rawMessageHashSignature = PkCrypto.rsaSignEncodedMessage(messageHash, TestCredentials.privateRSAKey);
      log.info("Raw RSA signing message hash: \n{}", TestUtils.base64Print(rawMessageHashSignature, 74));
      byte[] decryptedEmSigned =
          PkCrypto.rsaVerifyEncodedMessage(rawMessageHashSignature, TestCredentials.publicRSAKey);
      log.info("Decrypted raw signed signature value: {}", Hex.toHexString(decryptedEmSigned));
      assertArrayEquals(messageHash, decryptedEmSigned);
      log.info("Raw encrypted data verification succeeded");
    }
  }

  @Test
  void ecdsaVerifyDigest() throws Exception {
    log.info("ECDSA sign and verify test");
    log.info("Signing string: \"Data to be signed\"");
    EcdsaSigValue ecdsaSigValue =
        PkCrypto.ecdsaSignData("Data to be signed".getBytes(StandardCharsets.UTF_8), TestCredentials.privateECKey,
            TestAlgorithms.ecdsaSha256);
    log.info("Concatenated signature bytes: \n{}", TestUtils.base64Print(ecdsaSigValue.toByteArray(), 74));
    log.info("DER encoded signature value: \n{}", TestUtils.base64Print(ecdsaSigValue.getDEREncodedSigValue(), 74));

    MessageDigest md = MessageDigest.getInstance(TestAlgorithms.sha256.getJcaName());
    byte[] messageHash = md.digest("Data to be signed".getBytes(StandardCharsets.UTF_8));
    log.info("Message hash {}", Hex.toHexString(messageHash));

    boolean verified = PkCrypto.ecdsaVerifyDigest(messageHash, ecdsaSigValue, TestCredentials.publicECKey);

    assertTrue(verified);
    log.info("EC signature verified");
  }

  @Test
  void getAlgorithmFromTypeAndDigestMethod() {
    log.info("Testing to derive algorithm from hash and key type");
    log.info("Getting algorithm for SHA-256 and EC");
    Algorithm algorithm = PkCrypto.getAlgorithmFromTypeAndDigestMethod(TestAlgorithms.sha256, "EC",
        AlgorithmRegistrySingleton.getInstance());
    log.info("Found algorithm: {}", algorithm.getUri());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", algorithm.getUri());
  }
}
