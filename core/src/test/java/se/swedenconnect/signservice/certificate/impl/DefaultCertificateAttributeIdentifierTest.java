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
package se.swedenconnect.signservice.certificate.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.CertificateAttributeType;

/**
 * Test cases for DefaultCertificateAttributeIdentifier.
 */
public class DefaultCertificateAttributeIdentifierTest {

  @Test
  public void testCtorNull() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultCertificateAttributeIdentifier(null, "2.5.4.6");
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultCertificateAttributeIdentifier(CertificateAttributeType.RDN, null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultCertificateAttributeIdentifier(CertificateAttributeType.RDN, "  ");
    });
  }

  @Test
  public void testUsage() {
    final DefaultCertificateAttributeIdentifier id =
        new DefaultCertificateAttributeIdentifier(CertificateAttributeType.RDN, "2.5.4.42", "givenName");
    Assertions.assertEquals(CertificateAttributeType.RDN, id.getType());
    Assertions.assertEquals("2.5.4.42", id.getIdentifier());
    Assertions.assertEquals("givenName", id.getFriendlyName());
    Assertions.assertEquals("[RDN] 2.5.4.42 (givenName)", id.toString());

    final DefaultCertificateAttributeIdentifier id2 =
        new DefaultCertificateAttributeIdentifier(CertificateAttributeType.RDN, "2.5.4.42");
    Assertions.assertEquals(CertificateAttributeType.RDN, id2.getType());
    Assertions.assertEquals("2.5.4.42", id2.getIdentifier());
    Assertions.assertNull(id2.getFriendlyName());
    Assertions.assertEquals("[RDN] 2.5.4.42", id2.toString());
  }

}
