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
package se.swedenconnect.signservice.authn.mock;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultAuthnRequirements;

/**
 * Test cases for MockedAuthenticationHandler.
 */
public class MockedAuthenticationHandlerTest {

  private static final String AUTHN_SERVICE_ID = "https://mock.example.com/idp";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
  private static final String UNCERTIFIED_LOA3 = "http://id.swedenconnect.se/loa/1.0/uncertified-loa3";

  private static final String SIGN_MESSAGE = "<csig:SignMessage\n"
      + "DisplayEntity=\"https://mock.example.com/idp\"\n"
      + "MimeType=\"text\" MustShow=\"true\" xmlns:csig=\"http://id.elegnamnden.se/csig/1.1/dss-ext/ns\">\n"
      + "<csig:Message>TWVzc2FnZSB0byBkaXNwbGF5</csig:Message>\n"
      + "</csig:SignMessage>";

  @Test
  public void testAuthenticate() throws UserAuthenticationException {
    final DefaultAuthnRequirements authnReqs = new DefaultAuthnRequirements();
    authnReqs.setAuthnServiceID(AUTHN_SERVICE_ID);
    authnReqs.setAuthnContextIdentifiers(Arrays.asList(
        new SimpleAuthnContextIdentifier(UNCERTIFIED_LOA3),
        new SimpleAuthnContextIdentifier(LOA3)));
    authnReqs.setRequestedSignerAttributes(Arrays.asList(
        new StringSamlIdentityAttribute("urn:oid:2.5.4.42", "givenName", "Kalle"),
        new StringSamlIdentityAttribute("urn:oid:2.5.4.4", "sn", "Kula")));

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getEncoding()).thenReturn(SIGN_MESSAGE.getBytes());

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final MockedAuthenticationHandler handler = new MockedAuthenticationHandler();
    handler.setName("mocked");
    Assertions.assertEquals("mocked", handler.getName());
    final AuthenticationResultChoice choice = handler.authenticate(authnReqs, signMessage, context);
    Assertions.assertNull(choice.getHttpRequestMessage());

    final AuthenticationResult result = choice.getAuthenticationResult();
    Assertions.assertNotNull(result);
    Assertions.assertTrue(result.signMessageDisplayed());
    Assertions.assertNotNull(result.getAssertion().getIdentifier());
    Assertions.assertEquals(AUTHN_SERVICE_ID, result.getAssertion().getIssuer());
    Assertions.assertEquals(UNCERTIFIED_LOA3, result.getAssertion().getAuthnContext().getIdentifier());

    Assertions.assertEquals(3, result.getAssertion().getIdentityAttributes().size());
  }

  @Test
  public void testCanProcess() {
    final MockedAuthenticationHandler handler = new MockedAuthenticationHandler();
    Assertions.assertEquals(MockedAuthenticationHandler.class.getSimpleName(), handler.getName());
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Assertions.assertFalse(handler.canProcess(request, null));
  }

  @Test
  public void testResumeAuthentication() {
    final MockedAuthenticationHandler handler = new MockedAuthenticationHandler();
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    Assertions.assertThrows(UserAuthenticationException.class, () -> {
      handler.resumeAuthentication(request, context);
    });

  }

}
