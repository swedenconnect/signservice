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
package se.swedenconnect.signservice.certificate.keyprovider;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * DefaultInMemoryECkeyProviderTests
 */
@Slf4j
class InMemoryECKeyProviderTest {

  @BeforeAll
  private static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void getKeyPair() throws Exception {

    testECKeyProvider("P-256", SECObjectIdentifiers.secp256r1);
    testECKeyProvider("P-384", SECObjectIdentifiers.secp384r1);
    testECKeyProvider("P-521", SECObjectIdentifiers.secp521r1);
  }

  private void testECKeyProvider(String curveName, ASN1ObjectIdentifier expectedNamedCurve) throws Exception {
    KeyProvider keyProvider = new InMemoryECKeyProvider(new ECGenParameterSpec(curveName));
    long startTime = System.currentTimeMillis();
    PkiCredential keyPair = keyProvider.getKeyPair();
    long generationTime = System.currentTimeMillis() - startTime;
    log.info("EC key with curve {} generated in {} ms", curveName, generationTime);

    ASN1ObjectIdentifier namedCurve = getNamedCurve(keyPair);
    assertEquals(expectedNamedCurve, namedCurve);
    log.info("Found expected named curve: {}", namedCurve);
  }

  public static ASN1ObjectIdentifier getNamedCurve(PkiCredential keyPair) throws Exception {

    try (ASN1InputStream ais = new ASN1InputStream(keyPair.getPublicKey().getEncoded())) {
      ASN1Sequence pubKeySeq = ASN1Sequence.getInstance(ais.readObject());
      AlgorithmIdentifier ecAlgorithmId = AlgorithmIdentifier.getInstance(pubKeySeq.getObjectAt(0));
      ASN1ObjectIdentifier namedCurve = ASN1ObjectIdentifier.getInstance(ecAlgorithmId.getParameters());
      return namedCurve;
    }
  }
}