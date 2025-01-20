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
package se.swedenconnect.signservice.certificate.base.config;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Test cases for KeyUsageCalculator.
 */
public class KeyUsageCalculatorTest {

  @Test
  public void testDefaults() {
    final int defaultKeyUsage = KeyUsage.digitalSignature + KeyUsage.nonRepudiation;

    Assertions.assertEquals(defaultKeyUsage,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(RSAPublicKey.class), null));
    Assertions.assertEquals(defaultKeyUsage,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(RSAPublicKey.class), new SigningKeyUsageDirective()));
    Assertions.assertEquals(defaultKeyUsage,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(ECPublicKey.class), null));
    Assertions.assertEquals(defaultKeyUsage,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(ECPublicKey.class), new SigningKeyUsageDirective()));
  }

  @Test
  public void testExcludeNr() {
    final SigningKeyUsageDirective directive = new SigningKeyUsageDirective();
    directive.setExcludeNonRepudiation(true);

    Assertions.assertEquals(KeyUsage.digitalSignature,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(RSAPublicKey.class), directive));
    Assertions.assertEquals(KeyUsage.digitalSignature,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(ECPublicKey.class), directive));
  }

  @Test
  public void testEncrypt() {
    final int defaultKeyUsage = KeyUsage.digitalSignature + KeyUsage.nonRepudiation;

    final SigningKeyUsageDirective directive = new SigningKeyUsageDirective();
    directive.setEncrypt(true);

    Assertions.assertEquals(defaultKeyUsage + KeyUsage.keyEncipherment,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(RSAPublicKey.class), directive));
    Assertions.assertEquals(defaultKeyUsage + KeyUsage.keyAgreement,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(ECPublicKey.class), directive));
  }

  @Test
  public void testExcludeNrAndEncrypt() {
    final SigningKeyUsageDirective directive = new SigningKeyUsageDirective();
    directive.setEncrypt(true);
    directive.setExcludeNonRepudiation(true);

    Assertions.assertEquals(KeyUsage.digitalSignature + KeyUsage.keyEncipherment,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(RSAPublicKey.class), directive));
    Assertions.assertEquals(KeyUsage.digitalSignature + KeyUsage.keyAgreement,
        KeyUsageCalculator.getKeyUsageValue(Mockito.mock(ECPublicKey.class), directive));
  }

}
