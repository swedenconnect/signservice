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
package se.swedenconnect.signservice.protocol.dss;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;

import javax.xml.bind.JAXBException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.engine.SignServiceErrorCode;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignerAuthnInfo;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.impl.DefaultCompletedSignatureTask;

/**
 * Test cases for DssSignResponseMessage.
 */
public class DssSignResponseMessageTest {

  private static DssSignRequestMessage signRequest;

  static {
    try {
      final Document doc =
          DOMUtils.inputStreamToDocument(DssSignResponseMessageTest.class.getResourceAsStream("/request.xml"));
      final SignRequest jaxb = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

      signRequest = new DssSignRequestMessage(jaxb, doc);
    }
    catch (final JAXBException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testCtorNullRequest() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DssSignResponseMessage(null, null);
    });
  }

  @Test
  public void testIncludeSignMessage() {
    final DssSignResponseMessage.ResponseConfiguration conf = new DssSignResponseMessage.ResponseConfiguration();
    conf.includeRequestMessage = true;
    final DssSignResponseMessage response = new DssSignResponseMessage(conf, signRequest);

    Assertions.assertTrue(
        DOMUtils.bytesToDocument(response.toString().getBytes()).getElementsByTagName("csig:Request").getLength() == 1);
  }

  @Test
  public void testSetSignErrorResult() {
    final DssSignResponseMessage response = new DssSignResponseMessage(null, signRequest);

    final DefaultIdentityAssertion identityAssertion = new DefaultIdentityAssertion();
    identityAssertion.setScheme("SAML");
    identityAssertion.setIdentifier("abc");
    identityAssertion.setAuthnInstant(Instant.now());
    identityAssertion.setAuthnContext(new SimpleAuthnContextIdentifier("loa3"));
    identityAssertion.setIssuer("idp");
    identityAssertion.setEncodedAssertion("bytes".getBytes());
    identityAssertion.setIdentityAttributes(Arrays.asList(
        new StringSamlIdentityAttribute("id", "friendly", "value")));

    final DefaultSignerAuthnInfo sai = new DefaultSignerAuthnInfo(identityAssertion);
    response.setSignerAuthnInfo(sai);

    Assertions.assertNotNull(response.getSignerAuthnInfo());

    // Set error result
    final SignServiceError error = new SignServiceError(SignServiceErrorCode.AUTHN_SIGNMESSAGE_NOT_DISPLAYED);
    final DssSignResponseResult result = new DssSignResponseResult(error);

    response.setSignResponseResult(result);

    Assertions.assertEquals(result, response.getSignResponseResult());

    // Also make sure that the signer auth info was removed (since this was an error).
    Assertions.assertNull(response.getSignerAuthnInfo());
  }

  @Test
  public void testCertificateChain() throws Exception {
    final X509Certificate cert = X509Utils.decodeCertificate(
        DssSignResponseMessageTest.class.getResourceAsStream("/cert1.crt"));

    final DssSignResponseMessage response = new DssSignResponseMessage(null, signRequest);

    response.setSignatureCertificateChain(Arrays.asList(cert));

    Assertions.assertEquals(cert, response.getSignatureCertificateChain().get(0));
  }

  @Test
  public void testSignTasks() {
    final DssSignResponseMessage response = new DssSignResponseMessage(null, signRequest);

    final DefaultCompletedSignatureTask task = new DefaultCompletedSignatureTask();
    task.setProcessingRulesUri("uri");
    task.setSignatureType(SignatureType.XML);
    task.setTbsData("tbs".getBytes());
    task.setTaskId("taskid");
    task.setSignature("signature".getBytes());
    task.setSignatureAlgorithmUri("rsa-sha256");
    task.setAdESType(AdESType.BES);
    final DefaultAdESObject ao = new DefaultAdESObject("id", "bytes".getBytes());
    task.setAdESObject(ao);

    response.setSignatureTasks(Arrays.asList(task));

    Assertions.assertEquals(task, response.getSignatureTasks().get(0));
  }

  @Test
  public void testSignTasksNull() {
    final DssSignResponseMessage response = new DssSignResponseMessage(null, signRequest);

    response.setSignatureTasks(Collections.emptyList());
    Assertions.assertNull(response.getSignatureTasks());

    response.setSignatureTasks(null);
    Assertions.assertNull(response.getSignatureTasks());
  }

}
