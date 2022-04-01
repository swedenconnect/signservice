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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements.SignatureRequirement;

/**
 * Test cases for DssSignRequestMessage.
 */
public class DssSignRequestMessageTest {

  @Test
  public void testCorrect1() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc, "relay-state");
    request.assertCorrectMessage();

    // Assert some fields
    Assertions.assertEquals("da655e67-1104-4ae0-994f-740811ece38d", request.getRequestId());
    Assertions.assertEquals("relay-state", request.getRelayState());
    Assertions.assertEquals("http://id.elegnamnden.se/loa/1.0/loa3",
        request.getAuthnRequirements().getAuthnContextIdentifiers().get(0).getIdentifier());
    Assertions.assertTrue(request.isSigned());

    // Verify the signature
    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getClass().getResourceAsStream("/cert1.crt"));
    request.verifySignature(Arrays.asList(cert));

    // Assert reqs
    Assertions.assertEquals(SignatureRequirement.REQUIRED, request.getProcessingRequirements().getRequestSignatureRequirement());
    Assertions.assertEquals(SignatureRequirement.REQUIRED, request.getProcessingRequirements().getResponseSignatureRequirement());
    Assertions.assertEquals("POST", request.getProcessingRequirements().getResponseSendMethod());
  }

  @Test
  public void testMissingRequestId() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    doc.getDocumentElement().removeAttribute("RequestID");
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc, "relay-state");

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });

  }

  @Test
  public void testBadProfile() throws Exception {
    // A missing Profile should work
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    doc.getDocumentElement().removeAttribute("Profile");
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc, "relay-state");
    request.assertCorrectMessage();

    // But not an unknown value
    doc.getDocumentElement().setAttribute("Profile", "not-a-valid-value");
    final SignRequest signRequest2 = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request2 = new DssSignRequestMessage(signRequest2, doc, "relay-state");

    Assertions.assertThrows(ProtocolException.class, () -> {
      request2.assertCorrectMessage();
    });

  }

  @Test
  public void testJavaSerialization() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc, "relay-state");

    // Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = new ObjectOutputStream(bos);
    out.writeObject(request);
    byte[] serialization = bos.toByteArray();
    Assertions.assertNotNull(serialization);

    // Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(serialization);
    ObjectInputStream in = new ObjectInputStream(bis);
    final DssSignRequestMessage request2 = (DssSignRequestMessage) in.readObject();
    Assertions.assertNotNull(request2);
    Assertions.assertEquals(request.getRequestId(), request2.getRequestId());

    request2.assertCorrectMessage();

    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getClass().getResourceAsStream("/cert1.crt"));
    request2.verifySignature(Arrays.asList(cert));
  }

  // TODO: Many more test cases ...

}
