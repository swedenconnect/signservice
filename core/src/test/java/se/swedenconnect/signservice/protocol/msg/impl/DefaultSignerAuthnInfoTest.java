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
import org.mockito.Mockito;

import se.swedenconnect.signservice.authn.IdentityAssertion;

/**
 * Test cases for DefaultSignerAuthnInfo.
 */
public class DefaultSignerAuthnInfoTest {

  @Test
  public void testNull() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultSignerAuthnInfo(null, null);
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultSignerAuthnInfo("SAML", null);
    });
  }

  @Test
  public void testUsage() {
    final IdentityAssertion ass = Mockito.mock(IdentityAssertion.class);
    Mockito.when(ass.toString()).thenReturn("assertion");

    final DefaultSignerAuthnInfo authnInfo = new DefaultSignerAuthnInfo("SAML", ass);
    Assertions.assertEquals("SAML", authnInfo.getScheme());
    Assertions.assertNotNull(authnInfo.getIdentityAssertion());
    Assertions.assertEquals("scheme='SAML', identity-assertion=[assertion]", authnInfo.toString());
  }

}