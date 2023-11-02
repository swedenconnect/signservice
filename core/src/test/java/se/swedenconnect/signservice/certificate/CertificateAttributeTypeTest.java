/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for CertificateAttributeType.
 */
public class CertificateAttributeTypeTest {

  @Test
  public void testFromType() {
    Assertions.assertEquals(CertificateAttributeType.RDN,
        CertificateAttributeType.fromType("RDN"));
    Assertions.assertEquals(CertificateAttributeType.RDN,
        CertificateAttributeType.fromType("rdn"));
    Assertions.assertEquals(CertificateAttributeType.RDN,
        CertificateAttributeType.fromType(CertificateAttributeType.RDN.getType()));

    Assertions.assertEquals(CertificateAttributeType.SAN,
        CertificateAttributeType.fromType("SAN"));
    Assertions.assertEquals(CertificateAttributeType.SAN,
        CertificateAttributeType.fromType("san"));
    Assertions.assertEquals(CertificateAttributeType.SAN,
        CertificateAttributeType.fromType(CertificateAttributeType.SAN.getType()));

    Assertions.assertEquals(CertificateAttributeType.SDA,
        CertificateAttributeType.fromType("SDA"));
    Assertions.assertEquals(CertificateAttributeType.SDA,
        CertificateAttributeType.fromType("sda"));
    Assertions.assertEquals(CertificateAttributeType.SDA,
        CertificateAttributeType.fromType(CertificateAttributeType.SDA.getType()));
  }

  @Test
  public void testUnkownType() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      CertificateAttributeType.fromType("unknown");
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      CertificateAttributeType.fromType(null);
    });
  }

}
