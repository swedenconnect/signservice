/*
 * Copyright 2022-2024 Sweden Connect
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

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.attribute.impl.DefaultIdentityAttributeIdentifier;

/**
 * Test cases for DefaultCertificateAttributeMapping.
 */
public class DefaultCertificateAttributeMappingTest {

  @Test
  public void testUsage() {
    final DefaultIdentityAttributeIdentifier s1 =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.29.4.13", null);
    final DefaultIdentityAttributeIdentifier s2 =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.201.3.15", null);

    final DefaultRequestedCertificateAttribute d = new DefaultRequestedCertificateAttribute(null, "2.5.1.4");
    d.setRequired(true);

    final DefaultCertificateAttributeMapping cam = new DefaultCertificateAttributeMapping();
    cam.setSources(Arrays.asList(s1, s2));
    cam.setDestination(d);

    Assertions.assertEquals(Arrays.asList(s1, s2), cam.getSources());
    Assertions.assertEquals(d, cam.getDestination());
    Assertions.assertNotNull(cam.toString());
  }

  @Test
  public void testEmptySource() {
    final DefaultCertificateAttributeMapping cam = new DefaultCertificateAttributeMapping();
    cam.setSources(null);
    cam.setDestination(new DefaultRequestedCertificateAttribute(null, "2.5.1.4"));

    Assertions.assertTrue(cam.getSources().isEmpty());
  }

}
