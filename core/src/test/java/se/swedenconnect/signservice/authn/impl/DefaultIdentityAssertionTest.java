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
package se.swedenconnect.signservice.authn.impl;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * Test cases for DefaultIdentityAssertion.
 */
public class DefaultIdentityAssertionTest {

  @Test
  public void testUsage() {
    final Instant ii = Instant.now();
    final Instant ai = ii.minusMillis(1000L);

    final DefaultIdentityAssertion a = new DefaultIdentityAssertion();
    a.setIdentifier("id");
    a.setIssuer("issuer");
    a.setIssuanceInstant(ii);
    a.setAuthnInstant(ai);
    a.setAuthnContext(new SimpleAuthnContextIdentifier("ctx-id"));

    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("issuer", a.getIssuer());
    Assertions.assertEquals(ii, a.getIssuanceInstant());
    Assertions.assertEquals(ai, a.getAuthnInstant());
    Assertions.assertEquals("ctx-id", a.getAuthnContext().getIdentifier());
    Assertions.assertTrue(a.getIdentityAttributes().isEmpty());
    Assertions.assertNull(a.getEncodedAssertion());
    Assertions.assertNotNull(a.toString());

    final List<IdentityAttribute<?>> list = Arrays.asList(
        new StringSamlIdentityAttribute("id", "friendly", "value"),
        new StringSamlIdentityAttribute("id2", "friendly2", "value2"));
    a.setIdentityAttributes(list);
    a.setEncodedAssertion("bytes".getBytes());

    Assertions.assertEquals(list, a.getIdentityAttributes());
    Assertions.assertArrayEquals("bytes".getBytes(), a.getEncodedAssertion());
    Assertions.assertNotNull(a.toString());
  }

}