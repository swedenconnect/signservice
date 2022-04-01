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
package se.swedenconnect.signservice.core.attribute.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for DefaultIdentityAttributeIdentifier.
 */
public class DefaultIdentityAttributeIdentifierTest {

  @Test
  public void testBadInit() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultIdentityAttributeIdentifier(null, null, null);
    });

    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultIdentityAttributeIdentifier("SAML", null, null);
    });
  }

  @Test
  public void testSimple() {
    final DefaultIdentityAttributeIdentifier id =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.29.4.13", "personalIdentityNumber");
    Assertions.assertEquals("SAML", id.getScheme());
    Assertions.assertEquals("urn:oid:1.2.752.29.4.13", id.getIdentifier());
    Assertions.assertEquals("personalIdentityNumber", id.getFriendlyName());
    Assertions.assertEquals("[SAML] urn:oid:1.2.752.29.4.13 (personalIdentityNumber)", id.toString());
  }

  @Test
  public void testNoFriendlyName() {
    final DefaultIdentityAttributeIdentifier id =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.29.4.13", "personalIdentityNumber");
    final DefaultIdentityAttributeIdentifier id2 =
        new DefaultIdentityAttributeIdentifier("SAML", "urn:oid:1.2.752.29.4.13", null);

    // They should still be the same
    Assertions.assertTrue(id.equals(id2) && id2.equals(id));
    Assertions.assertTrue(id.hashCode() == id2.hashCode());

    // toString
    Assertions.assertEquals("[SAML] urn:oid:1.2.752.29.4.13", id2.toString());
  }

}
