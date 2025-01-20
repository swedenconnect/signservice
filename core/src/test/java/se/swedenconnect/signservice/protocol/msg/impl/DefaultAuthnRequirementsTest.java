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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * Test cases for DefaultAuthnRequirements.
 */
public class DefaultAuthnRequirementsTest {

  @Test
  public void testUsage() {
    final DefaultAuthnRequirements ar = new DefaultAuthnRequirements();
    ar.setAuthnProfile("default");
    ar.setAuthnContextIdentifiers(Arrays.asList(
        new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3"),
        new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa4")));
    ar.setAuthnServiceID("http://idp.example.com");
    ar.setRequestedSignerAttributes(Arrays.asList(
        new StringSamlIdentityAttribute("urn:oid:1.2.752.29.4.13", null, "199001011809")));
    ar.setSignatureActivationRequestData(new DefaultSignatureActivationRequestData("ID", 2, false));

    Assertions.assertEquals("default", ar.getAuthnProfile());
    Assertions.assertEquals(Arrays.asList(
        new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3"),
        new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa4")), ar.getAuthnContextIdentifiers());
    Assertions.assertEquals("http://idp.example.com", ar.getAuthnServiceID());
    Assertions.assertEquals(Arrays.asList(
        new StringSamlIdentityAttribute("urn:oid:1.2.752.29.4.13", null, "199001011809")),
        ar.getRequestedSignerAttributes());
    Assertions.assertEquals("ID", ar.getSignatureActivationRequestData().getSignRequestId());
    Assertions.assertEquals(2, ar.getSignatureActivationRequestData().getDocumentCount());
    Assertions.assertFalse(ar.getSignatureActivationRequestData().isRequired());
    Assertions.assertNotNull(ar.toString());
  }

  @Test
  public void testEmpty() {
    final DefaultAuthnRequirements ar = new DefaultAuthnRequirements();
    ar.setAuthnContextIdentifiers(null);
    ar.setRequestedSignerAttributes(null);

    Assertions.assertTrue(ar.getAuthnContextIdentifiers().isEmpty());
    Assertions.assertTrue(ar.getRequestedSignerAttributes().isEmpty());
  }

}
