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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.core.attribute.impl.DefaultIdentityAttributeIdentifier;

/**
 * Test cases for DefaultSigningCertificateRequirements.
 */
public class DefaultSigningCertificateRequirementsTest {

  @Test
  public void testUsage() {
    final DefaultSigningCertificateRequirements reqs = new DefaultSigningCertificateRequirements();
    reqs.setSigningCertificateProfile("policy");
    reqs.setCertificateType(CertificateType.PKC);

    final DefaultIdentityAttributeIdentifier s1 =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.29.4.13", null);
    final DefaultIdentityAttributeIdentifier s2 =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.201.3.15", null);

    final DefaultRequestedCertificateAttribute d = new DefaultRequestedCertificateAttribute(null, "2.5.1.4");
    d.setRequired(true);

    final DefaultCertificateAttributeMapping cam = new DefaultCertificateAttributeMapping();
    cam.setSources(Arrays.asList(s1, s2));
    cam.setDestination(d);

    reqs.setAttributeMappings(Arrays.asList(cam));

    Assertions.assertEquals("policy", reqs.getSigningCertificateProfile());
    Assertions.assertEquals(CertificateType.PKC, reqs.getCertificateType());
    Assertions.assertEquals(Arrays.asList(cam), reqs.getAttributeMappings());
    Assertions.assertNotNull(reqs.toString());

    reqs.setAttributeMappings(null);
    Assertions.assertTrue(reqs.getAttributeMappings().isEmpty());
  }

}
