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
import org.w3c.dom.Element;

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

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    // Assert some fields
    Assertions.assertEquals("da655e67-1104-4ae0-994f-740811ece38d", request.getRequestId());
    Assertions.assertEquals("da655e67-1104-4ae0-994f-740811ece38d", request.getRelayState());
    Assertions.assertEquals("http://id.elegnamnden.se/loa/1.0/loa3",
        request.getAuthnRequirements().getAuthnContextIdentifiers().get(0).getIdentifier());
    Assertions.assertEquals(request.getRequestId(),
        request.getAuthnRequirements().getSignatureActivationRequestData().getSignRequestId());
    Assertions.assertFalse(request.getAuthnRequirements().getSignatureActivationRequestData().isRequired());
    Assertions.assertTrue(request.isSigned());

    Assertions.assertNotNull(request.getJaxbObject());
    Assertions.assertNotNull(request.toString());

    // Verify the signature
    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getClass().getResourceAsStream("/cert1.crt"));
    request.verifySignature(Arrays.asList(cert));

    // Assert reqs
    Assertions.assertEquals(SignatureRequirement.REQUIRED,
        request.getProcessingRequirements().getRequestSignatureRequirement());
    Assertions.assertEquals(SignatureRequirement.REQUIRED,
        request.getProcessingRequirements().getResponseSignatureRequirement());
    Assertions.assertEquals("POST", request.getProcessingRequirements().getResponseSendMethod());
  }

  @Test
  public void testMissingRequestId() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    doc.getDocumentElement().removeAttribute("RequestID");
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

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

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    // But not an unknown value
    doc.getDocumentElement().setAttribute("Profile", "not-a-valid-value");
    final SignRequest signRequest2 = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request2 = new DssSignRequestMessage(signRequest2, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request2.assertCorrectMessage();
    });
  }

  @Test
  public void testVersion() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:SignRequestExtension").item(0);

    // Too low version
    e.setAttribute("Version", "1.0");
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });

    // Too high version
    e.setAttribute("Version", "2.0");
    final SignRequest signRequest2 = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request2 = new DssSignRequestMessage(signRequest2, doc);
    Assertions.assertThrows(ProtocolException.class, () -> {
      request2.assertCorrectMessage();
    });

    // Missing version - should be ok
    e.removeAttribute("Version");
    final SignRequest signRequest3 = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request3 = new DssSignRequestMessage(signRequest3, doc);
    Assertions.assertDoesNotThrow(() -> {
      request3.assertCorrectMessage();
    });

    // Invalid version
    e.setAttribute("Version", "foobar");
    final SignRequest signRequest4 = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request4 = new DssSignRequestMessage(signRequest4, doc);
    Assertions.assertThrows(ProtocolException.class, () -> {
      request4.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingSignTasks() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement()
        .getElementsByTagName("dss:InputDocuments").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingSignTaskId() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-missing-signtaskid.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingSignTaskIdOneTask() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-one-task-missing-signtaskid.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    // If the SignTaskID is missing and we only have one task it is ok
    Assertions.assertDoesNotThrow(() -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingSignatureType() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-missing-signature-type.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingTbsData() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-missing-tbs.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingSignRequestExtension() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-missing-ext.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testNoRequestTime() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:RequestTime").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingConditions() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("saml2:Conditions").item(0);

    // No NotBefore
    {
      final String notBefore = e.getAttribute("NotBefore");
      e.removeAttribute("NotBefore");
      final DssSignRequestMessage request =
          new DssSignRequestMessage(JAXBUnmarshaller.unmarshall(doc, SignRequest.class), doc);
      Assertions.assertThrows(ProtocolException.class, () -> {
        request.assertCorrectMessage();
      }, "Conditions.notBefore is missing - this field is required");
      e.setAttribute("NotBefore", notBefore);
    }

    // No NotOnOrAfter
    {
      final String notOnOrAfter = e.getAttribute("NotOnOrAfter");
      e.removeAttribute("NotOnOrAfter");
      final DssSignRequestMessage request =
          new DssSignRequestMessage(JAXBUnmarshaller.unmarshall(doc, SignRequest.class), doc);
      Assertions.assertThrows(ProtocolException.class, () -> {
        request.assertCorrectMessage();
      }, "Conditions.notOnOrAfter is missing - this field is required");
      e.setAttribute("NotOnOrAfter", notOnOrAfter);
    }

    // Missing audience
    {
      e.removeChild(e.getElementsByTagName("saml2:AudienceRestriction").item(0));
      final DssSignRequestMessage request =
          new DssSignRequestMessage(JAXBUnmarshaller.unmarshall(doc, SignRequest.class), doc);
      Assertions.assertThrows(ProtocolException.class, () -> {
        request.assertCorrectMessage();
      }, "Conditions.AudienceRestriction is missing - the response URL must be given here");
    }

    // Missing Conditions
    {
      e.getParentNode().removeChild(e);
      final DssSignRequestMessage request =
          new DssSignRequestMessage(JAXBUnmarshaller.unmarshall(doc, SignRequest.class), doc);
      Assertions.assertThrows(ProtocolException.class, () -> {
        request.assertCorrectMessage();
      }, "Conditions is missing - this element is required");
    }
  }

  @Test
  public void testMissingSigner() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-missing-signer.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    Assertions.assertTrue(request.getAuthnRequirements().getRequestedSignerAttributes().isEmpty());
  }

  @Test
  public void testBadAttributes() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-bad-attributes.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testMissingIdp() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:IdentityProvider").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    }, "IdentityProvider is missing - this field is required");
  }

  @Test
  public void testMissingSignRequester() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:SignRequester").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    }, "SignRequester is missing - this field is required");
  }

  @Test
  public void testMissingSignService() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:SignService").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    }, "SignService is missing - this field is required");
  }

  @Test
  public void testMissingAlgorithm() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e =
        (Element) doc.getDocumentElement().getElementsByTagName("csig:RequestedSignatureAlgorithm").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    }, "RequestedSignatureAlgorithm is missing - this field is required");
  }

  @Test
  public void testNoSignMessage() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:SignMessage").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    Assertions.assertNull(request.getSignMessage());
  }

  @Test
  public void testMissingSignMessageMessage() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:EncryptedMessage").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    }, "Bad SignMessage provided - either Message or EncryptedMessage must be assigned");
  }

  @Test
  public void testAuthnProfile() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-authnprofile.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    Assertions.assertEquals("AUTHNPROFILE", request.getAuthnRequirements().getAuthnProfile());

    // AuthnProfile should work (even for older versions) ...
    final Document doc2 =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-profile-v1_1.xml"));

    final SignRequest signRequest2 = JAXBUnmarshaller.unmarshall(doc2, SignRequest.class);
    final DssSignRequestMessage request2 = new DssSignRequestMessage(signRequest2, doc);

    request2.assertCorrectMessage();

    Assertions.assertEquals("AUTHNPROFILE", request2.getAuthnRequirements().getAuthnProfile());
  }

  @Test
  public void testNoCertReqProperties() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));

    final Element e = (Element) doc.getDocumentElement().getElementsByTagName("csig:CertRequestProperties").item(0);
    e.getParentNode().removeChild(e);

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);
    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);
    request.assertCorrectMessage();

    Assertions.assertNull(request.getSigningCertificateRequirements());
  }

  @Test
  public void testBadCertReqProperties() throws Exception {
    final Document doc =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request-bad-certreqprops.xml"));

    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

    Assertions.assertThrows(ProtocolException.class, () -> {
      request.assertCorrectMessage();
    });
  }

  @Test
  public void testJavaSerialization() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    final SignRequest signRequest = JAXBUnmarshaller.unmarshall(doc, SignRequest.class);

    final DssSignRequestMessage request = new DssSignRequestMessage(signRequest, doc);

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
