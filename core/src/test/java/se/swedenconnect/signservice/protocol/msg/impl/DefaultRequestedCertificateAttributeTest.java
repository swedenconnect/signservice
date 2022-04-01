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
package se.swedenconnect.signservice.protocol.msg.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.CertificateAttributeType;

/**
 * Test cases for DefaultRequestedCertificateAttribute.
 */
public class DefaultRequestedCertificateAttributeTest {

  @Test
  public void testRdnDefault() {
    final DefaultRequestedCertificateAttribute rca = new DefaultRequestedCertificateAttribute(null, "2.5.4.12");
    Assertions.assertEquals(CertificateAttributeType.RDN, rca.getType());
  }

  @Test
  public void testRequiredDefault() {
    final DefaultRequestedCertificateAttribute rca =
        new DefaultRequestedCertificateAttribute(CertificateAttributeType.RDN, "2.5.4.12");
    Assertions.assertFalse(rca.isRequired());
  }

  @Test
  public void testUsage() {
    final DefaultRequestedCertificateAttribute rca =
        new DefaultRequestedCertificateAttribute(CertificateAttributeType.RDN, "2.5.4.12");
    rca.setDefaultValue("Hello");
    rca.setRequired(true);

    Assertions.assertEquals("2.5.4.12", rca.getIdentifier());
    Assertions.assertEquals("Hello", rca.getDefaultValue());
    Assertions.assertTrue(rca.isRequired());
    Assertions.assertNotNull(rca.toString());
  }

}
