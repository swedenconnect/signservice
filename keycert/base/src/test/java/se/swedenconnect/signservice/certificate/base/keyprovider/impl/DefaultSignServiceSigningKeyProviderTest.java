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
package se.swedenconnect.signservice.certificate.base.keyprovider.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;

import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DefaultSignServiceSigningKeyProviderTests
 */
@Slf4j
class DefaultSignServiceSigningKeyProviderTest {

  @BeforeAll
  private static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void testSigningKeyProvider() throws Exception {
    SignServiceSigningKeyProvider defaultKeyProvider = new DefaultSignServiceSigningKeyProvider();
    List<String> supportedKeyTypes = defaultKeyProvider.getSupportedKeyTypes();
    assertEquals(2, supportedKeyTypes.size());
    assertTrue(supportedKeyTypes.contains("EC"));
    assertTrue(supportedKeyTypes.contains("RSA"));

    testEcKey(defaultKeyProvider.getSigningKeyPair("EC"), SECObjectIdentifiers.secp256r1);
    testRSAKey(defaultKeyProvider.getSigningKeyPair("RSA", null), 3072);

    SignServiceSigningKeyProvider keyProvider = new DefaultSignServiceSigningKeyProvider(2048, 5,
      new ECGenParameterSpec("P-521"));
    testEcKey(keyProvider.getSigningKeyPair("EC", null), SECObjectIdentifiers.secp521r1);
    testRSAKey(keyProvider.getSigningKeyPair("RSA"), 2048);
  }

  private void testRSAKey(PkiCredential keyPair, int keyLen) {
    assertTrue(keyPair.getPublicKey() instanceof RSAPublicKey);
    log.info("Key is an RSA key");
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublicKey();
    assertEquals(keyLen, rsaPublicKey.getModulus().bitLength());
    log.info("Generated expected RSA key with key length {}", keyLen);
  }

  private void testEcKey(PkiCredential keyPair, ASN1ObjectIdentifier curveOID) throws Exception {
    assertTrue(keyPair.getPublicKey() instanceof ECPublicKey);
    log.info("Key is an EC key");
    ASN1ObjectIdentifier namedCurve = DefaultInMemoryECkeyProviderTest.getNamedCurve(keyPair);
    assertEquals(curveOID, namedCurve);
    log.info("Generated expected EC key using named curve {}", curveOID);
  }

}