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
package se.swedenconnect.signservice.certificate.simple;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultSAMLAttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultValuePolicyChecker;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.InMemoryECKeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.OnDemandInMemoryRSAKeyProvider;
import se.swedenconnect.signservice.certificate.simple.ca.BasicCAService;
import se.swedenconnect.signservice.certificate.simple.ca.CACertificateFactory;
import se.swedenconnect.signservice.certificate.simple.ca.CAServiceBuilder;
import se.swedenconnect.signservice.certificate.simple.ca.impl.DefaultCACertificateFactory;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultCertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultRequestedCertificateAttribute;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.impl.DefaultSignServiceContext;

/**
 * Tests for the simple key and certificate handler
 */
@Slf4j
class SimpleKeyAndCertificateHandlerTest {

  private static File caDir;

  @BeforeAll
  private static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    caDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
  }

  @Test
  void simpleKeyAndCertificateHandlerTest() throws Exception {
    log.info("Simple key and certificate handler tests");
    log.info("Created key provider");

    AlgorithmRegistrySingleton algorithmRegistry = AlgorithmRegistrySingleton.getInstance();

    InMemoryECKeyProvider ecProvider = new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"));
    PkiCredential caKeyPair = ecProvider.getKeyPair();
    log.info("CA key pair generated");
    CACertificateFactory caCertificateFactory = new DefaultCACertificateFactory();
    X509CertificateHolder caCertificate = caCertificateFactory.getCACertificate(
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
        new ExplicitCertNameModel(List.of(
            new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
            new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
            new AttributeTypeAndValueModel(CertAttributes.C, "SE"))),
        caKeyPair);
    log.info("CA Certificate generated\n{}", new PrintCertificate(caCertificate).toString(true, true, true));

    BasicCAService caService = CAServiceBuilder.getInstance(caKeyPair.getPrivateKey(), List.of(caCertificate),
        "http://localholst://crldp",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, new File(caDir, "kht-ca.crl")).build();

    AttributeMapper attributeMapper = new DefaultSAMLAttributeMapper(new DefaultValuePolicyChecker() {
      @Override
      public boolean isDefaultValueAllowed(CertificateAttributeType attributeType, String ref, String value) {
        return attributeType.equals(CertificateAttributeType.RDN) && ref.equalsIgnoreCase(CertAttributes.C.getId())
            && value.equalsIgnoreCase("SE");
      }
    });

    KeyAndCertificateHandler keyAndCertificateHandler = new SimpleKeyAndCertificateHandler(
        Arrays.asList(new OnDemandInMemoryRSAKeyProvider(2048),
            new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))),
        attributeMapper, algorithmRegistry, caService);
    assertEquals("SimpleKeyAndCertificateHandler", keyAndCertificateHandler.getName());
    log.info("Created key and certificate handler with name: {}", keyAndCertificateHandler.getName());
    ((SimpleKeyAndCertificateHandler) keyAndCertificateHandler).setName("test-cert-and-key-handler");
    assertEquals("test-cert-and-key-handler", keyAndCertificateHandler.getName());
    log.info("Updated key and certificate handler with name: {}", keyAndCertificateHandler.getName());

    keyAndCertificateHandler.checkRequirements(getCheckRequirementsRequest(CertificateType.PKC, "client-01"), null);
    log.info("Testing support for PKC certificates successful");
    InvalidRequestException e1 = assertThrows(InvalidRequestException.class,
        () -> keyAndCertificateHandler.checkRequirements(getCheckRequirementsRequest(CertificateType.QC, "client-01"),
            null));
    log.info("Caught exception when checking requirements: {}", e1.toString());

    testKeyAndCertGeneration("Normal ECDSA test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal RSA test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal RSA-PSS test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.allAttributeMappings, null);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        keyAndCertificateHandler, "Bad algorithm",
        "client01", CertificateType.PKC,
        null, TestData.allAttributeMappings, InvalidRequestException.class);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.QC,
        null, TestData.allAttributeMappings, InvalidRequestException.class);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, null, CertificateException.class);

  }

  void testKeyAndCertGeneration(String message, KeyAndCertificateHandler keyAndCertificateHandler,
      String signServiceSignAlo,
      String clientId, CertificateType certificateType, String profile,
      List<CertificateAttributeMapping> attributeMappings, Class<? extends Exception> exceptionClass) throws Exception {

    log.info(message);
    if (exceptionClass == null) {
      SignRequestMessage signRequest = getSignRequest(
          signServiceSignAlo, clientId, certificateType, profile, attributeMappings);

      SignServiceContext context = new DefaultSignServiceContext("context-id");
      keyAndCertificateHandler.checkRequirements(signRequest, context);
      log.info("Checked requirements for sign request OK");
      PkiCredential pkiCredential = keyAndCertificateHandler.generateSigningCredential(signRequest,
          TestData.stdAssertion,
          context);

      log.info("Issued certificate from CA:\n{}\n{}",
          new PrintCertificate(pkiCredential.getCertificate()).toString(true, true, true),
          new PrintCertificate(pkiCredential.getCertificate()).toPEM());
      return;
    }

    Exception exception = assertThrows(exceptionClass, () -> {
      SignRequestMessage signRequest = getSignRequest(
          signServiceSignAlo, clientId, certificateType, profile, attributeMappings);

      SignServiceContext context = new DefaultSignServiceContext("context-id");
      keyAndCertificateHandler.checkRequirements(signRequest, context);
      log.info("Checked requirements for sign request OK");
      keyAndCertificateHandler.generateSigningCredential(signRequest,
          TestData.stdAssertion,
          context);
    });
    log.info("Caught appropriate exception: {}", exception.toString());
  }

  private SignRequestMessage getCheckRequirementsRequest(CertificateType certificateType, String clientId) {
    return getSignRequest(
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        clientId,
        certificateType,
        null,
        TestData.defaultAttributeMappings);
  }

  private SignRequestMessage getSignRequest(String signatureAlgorithm, String clientId,
      CertificateType certType, String profile, List<CertificateAttributeMapping> attributeMappings) {
    SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(certificateRequirements.getCertificateType()).thenReturn(certType);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(profile);
    when(certificateRequirements.getAttributeMappings()).thenReturn(attributeMappings);

    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn(clientId);
    return signRequestMessage;
  }

  static class TestData {

    static IdentityAssertion stdAssertion = getTestAssertion();
    static List<CertificateAttributeMapping> defaultAttributeMappings = getDefaultAttributeMappings(false, false);
    static List<CertificateAttributeMapping> sanAttributeMappings = getDefaultAttributeMappings(true, false);
    static List<CertificateAttributeMapping> sdaAttributeMappings = getDefaultAttributeMappings(false, true);
    static List<CertificateAttributeMapping> allAttributeMappings = getDefaultAttributeMappings(true, true);

    private static List<CertificateAttributeMapping> getDefaultAttributeMappings(boolean san, boolean sda) {
      List<CertificateAttributeMapping> attrMapList = new ArrayList<>();
      attrMapList.add(getMapping(CertAttributes.SERIALNUMBER.getId(), CertificateAttributeType.RDN,
          "givenName", true, null, new String[] { "urn:oid:1.2.752.29.4.13" }));
      attrMapList.add(getMapping(CertAttributes.C.getId(), CertificateAttributeType.RDN,
          "country", true, "SE", new String[] { "urn:oid:2.5.4.6" }));
      attrMapList.add(getMapping(CertAttributes.GIVENNAME.getId(), CertificateAttributeType.RDN,
          "givenName", true, null, new String[] { "urn:oid:2.5.4.42" }));
      attrMapList.add(getMapping(CertAttributes.SURNAME.getId(), CertificateAttributeType.RDN,
          "surname", true, null, new String[] { "urn:oid:2.5.4.4" }));
      attrMapList.add(getMapping(CertAttributes.CN.getId(), CertificateAttributeType.RDN,
          "surname", true, null, new String[] { "urn:oid:2.16.840.1.113730.3.1.241", "urn:oid:2.5.4.3" }));

      if (san) {
        attrMapList.add(getMapping("2", CertificateAttributeType.SAN,
            "dnsName", false, null, new String[] { "urn:oid:" + CertAttributes.DC.getId() }));
      }
      if (sda) {
        attrMapList.add(getMapping(CertAttributes.DATE_OF_BIRTH.getId(), CertificateAttributeType.SDA,
            "dateOfBirth", false, null, new String[] { "urn:oid:" + CertAttributes.DATE_OF_BIRTH.getId() }));
      }
      return attrMapList;
    }

    private static CertificateAttributeMapping getMapping(String identifier, CertificateAttributeType attributeType,
        String friendlyName,
        boolean required, String defaultVal, String[] sourceIdArray) {
      DefaultCertificateAttributeMapping mapping = new DefaultCertificateAttributeMapping();
      DefaultRequestedCertificateAttribute destAttr = new DefaultRequestedCertificateAttribute(
          attributeType, identifier, friendlyName);
      destAttr.setRequired(required);
      destAttr.setDefaultValue(defaultVal);
      mapping.setDestination(destAttr);
      mapping.setSources(Arrays.stream(sourceIdArray)
          .map(MappedAttrSouce::new)
          .collect(Collectors.toList()));
      return mapping;
    }

    private static IdentityAssertion getTestAssertion() {
      IdentityAssertion assertion = mock(IdentityAssertion.class);
      when(assertion.getIdentityAttributes()).thenReturn(List.of(
          getMockAttr(CertAttributes.GIVENNAME.getId(), "Nisse", "Given name"),
          getMockAttr(CertAttributes.SURNAME.getId(), "Hult", "Surname"),
          getMockAttr("1.2.752.29.4.13", "1234567890", "Personal identity number"),
          getMockAttr(CertAttributes.CN.getId(), "Nisse Hult", "Common name"),
          getMockAttr(CertAttributes.DC.getId(), "example.com", "DNS name"),
          getMockAttr(CertAttributes.GENDER.getId(), "M", "Gender"),
          getMockAttr(CertAttributes.DATE_OF_BIRTH.getId(), "1992-05-15", "Gender")));
      when(assertion.getIdentifier()).thenReturn("a092384092384092384092834098234092834");
      when(assertion.getAuthnContext()).thenReturn(
          new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3"));
      when(assertion.getIssuer()).thenReturn("http://id.swedenconnect.se/idp");
      when(assertion.getAuthnInstant()).thenReturn(Instant.ofEpochMilli(System.currentTimeMillis()));
      return assertion;
    }

    private static IdentityAttribute<?> getMockAttr(String oidString, String value, String friendlyName) {
      return new StringSamlIdentityAttribute("urn:oid:" + oidString, friendlyName, value);
    }

  }

  @Data
  static class MappedAttrSouce implements IdentityAttributeIdentifier {

    private static final long serialVersionUID = 1201012063745204703L;

    public MappedAttrSouce(String identifier) {
      this.identifier = identifier;
    }

    String scheme;
    String identifier;
    String friendlyName;
  }

}