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
package se.swedenconnect.signservice.authn.saml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;

import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * Test cases for MessageReplayCheckerWrapper.
 */
public class MessageReplayCheckerWrapperTest extends OpenSamlTestBase {

  @Test
  public void testWrapper() throws Exception {
    final MessageReplayCheckerWrapper wrapper = new MessageReplayCheckerWrapper(new DummyChecker(false));
    wrapper.checkReplay("id");

    final MessageReplayCheckerWrapper wrapper2 = new MessageReplayCheckerWrapper(new DummyChecker(true));
    Assertions.assertThrows(se.swedenconnect.opensaml.saml2.response.replay.MessageReplayException.class, () -> {
      wrapper2.checkReplay("id");
    });
  }

  @Test
  public void testOpenSamlObjects() throws Exception {
    final MessageReplayCheckerWrapper wrapper = new MessageReplayCheckerWrapper(new DummyChecker(false));

    final Response response = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
    response.setID("ID");
    wrapper.checkReplay(response);

    final Assertion assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
    assertion.setID("ID");
    wrapper.checkReplay(assertion);

    final AuthnRequest obj = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      wrapper.checkReplay(obj);
    });
  }

  private static class DummyChecker implements se.swedenconnect.signservice.storage.MessageReplayChecker {

    private final boolean err;

    public DummyChecker(boolean err) {
      this.err = err;
    }

    @Override
    public void checkReplay(final String id) throws MessageReplayException {
      if (this.err) {
        throw new MessageReplayException("Exception");
      }
    }

  }

}
