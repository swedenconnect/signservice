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
package se.swedenconnect.signservice.certificate.simple;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.simple.ca.BasicCAServiceBuilder;
import se.swedenconnect.signservice.certificate.simple.ca.DefaultSelfSignedCaCertificateGenerator;
import se.swedenconnect.signservice.certificate.simple.ca.SelfSignedCaCertificateGenerator;
import se.swedenconnect.signservice.context.DefaultSignServiceContext;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpBodyAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultCertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultRequestedCertificateAttribute;

/**
 * Tests for the simple key and certificate handler
 */
@Slf4j
class SimpleKeyAndCertificateHandlerTest {

  private static CAService caService;

  private static X509Certificate caCertificate;

  private static AttributeMapper defaultAttributeMapper;

  private static SimpleKeyAndCertificateHandler defaultHandler;

  private static String crlPath = "/crl/cacrl.crl";

  private static String TEST_PATH = "target/test/ca-repo";
  private static String TEST_CRL = "kht-ca.crl";

  @BeforeAll
  public static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    final File caDir = new File(TEST_PATH);


    final PkiCredentialContainer ecProvider = new SoftPkiCredentialContainer("BC", "Test1234");
    final PkiCredential caCredential = ecProvider.getCredential(ecProvider.generateCredential(KeyGenType.EC_P256));

    final SelfSignedCaCertificateGenerator caCertGenerator = new DefaultSelfSignedCaCertificateGenerator();
    caCertificate = caCertGenerator.generate(
        caCredential,
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, Duration.ofDays(3650)),
        new ExplicitCertNameModel(List.of(
            new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
            new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
            new AttributeTypeAndValueModel(CertAttributes.C, "SE"))));
    caCredential.setCertificate(caCertificate);
    log.info("CA Certificate generated\n{}", new PrintCertificate(caCertificate).toString(true, true, true));

    caService = BasicCAServiceBuilder.getInstance(caCredential, "http://localhost://crldp",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, new File(caDir, TEST_CRL).getAbsolutePath()).build();

    defaultAttributeMapper =
        new DefaultAttributeMapper((attributeType, ref, value) -> attributeType.equals(CertificateAttributeType.RDN)
            && ref.equalsIgnoreCase(CertAttributes.C.getId())
            && value.equalsIgnoreCase("SE"));

    defaultHandler = new SimpleKeyAndCertificateHandler(
        new SoftPkiCredentialContainer("BC", "Test1234"), null, defaultAttributeMapper, null, caService, crlPath);
  }

  @AfterAll
  public static void clean() throws Exception {
    FileUtils.deleteDirectory(new File(TEST_PATH));
  }

  @Test
  public void testIssuanceEcdsa() throws Exception {
    final PkiCredential credential = defaultHandler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null,
            TestData.defaultAttributeMappings),
        TestData.stdAssertion,
        new DefaultSignServiceContext("id"));

    assertDoesNotThrow(() -> credential.getCertificate().verify(caCertificate.getPublicKey()));

    log.info("Issued certificate from CA:\n{}\n{}",
        new PrintCertificate(credential.getCertificate()).toString(true, true, true),
        new PrintCertificate(credential.getCertificate()).toPEM());
  }

  @Test
  public void testIssuanceRsa() throws Exception {
    final PkiCredential credential = defaultHandler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, CertificateType.PKC, null,
            TestData.defaultAttributeMappings),
        TestData.stdAssertion,
        new DefaultSignServiceContext("id"));

    assertDoesNotThrow(() -> credential.getCertificate().verify(caCertificate.getPublicKey()));

    log.info("Issued certificate from CA:\n{}\n{}",
        new PrintCertificate(credential.getCertificate()).toString(true, true, true),
        new PrintCertificate(credential.getCertificate()).toPEM());
  }

  @Test
  public void testIssuanceRsaPss() throws Exception {
    final PkiCredential credential = defaultHandler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, CertificateType.PKC, null,
            TestData.defaultAttributeMappings),
        TestData.stdAssertion,
        new DefaultSignServiceContext("id"));

    assertDoesNotThrow(() -> credential.getCertificate().verify(caCertificate.getPublicKey()));

    log.info("Issued certificate from CA:\n{}\n{}",
        new PrintCertificate(credential.getCertificate()).toString(true, true, true),
        new PrintCertificate(credential.getCertificate()).toPEM());
  }

  @Test
  public void testSanAndSubjDirAttrs() throws Exception {
    final PkiCredential credential = defaultHandler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null,
            TestData.allAttributeMappings),
        TestData.stdAssertion,
        new DefaultSignServiceContext("id"));

    assertDoesNotThrow(() -> credential.getCertificate().verify(caCertificate.getPublicKey()));

    // TODO: Should examine issued cert for SAN and Subj dir

    log.info("Issued certificate from CA:\n{}\n{}",
        new PrintCertificate(credential.getCertificate()).toString(true, true, true),
        new PrintCertificate(credential.getCertificate()).toPEM());
  }

  @Test
  public void testBadProfile() throws Exception {

    assertThatThrownBy(() -> {
      defaultHandler.checkRequirements(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, CertificateType.PKC, "bad-profile",
              TestData.defaultAttributeMappings),
          new DefaultSignServiceContext("id"));
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("This handler does not support profile: bad-profile");

    // This should be ok
    assertDoesNotThrow(() -> defaultHandler.checkRequirements(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, CertificateType.PKC, "",
            TestData.defaultAttributeMappings),
        new DefaultSignServiceContext("id")));
  }

  @Test
  public void testBadCertificateIssued() throws Exception {
    final X509CertificateHolder holder = Mockito.mock(X509CertificateHolder.class);
    Mockito.when(holder.getEncoded()).thenReturn("not-valid".getBytes());

    final AbstractCertificateModelBuilder<?> modelBuilder = Mockito.mock(AbstractCertificateModelBuilder.class);

    CAService mockedCa = Mockito.mock(CAService.class);
    Mockito.when(mockedCa.issueCertificate(Mockito.any())).thenReturn(holder);
    Mockito.when(mockedCa.getCertificateModelBuilder(Mockito.any(), Mockito.any())).thenReturn(modelBuilder);

    final SimpleKeyAndCertificateHandler handler = new SimpleKeyAndCertificateHandler(
        new SoftPkiCredentialContainer("BC", "Test1234"), null, defaultAttributeMapper,
        null, mockedCa, crlPath);

    assertThatThrownBy(() -> {
      handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, CertificateType.PKC, null,
              TestData.defaultAttributeMappings),
          TestData.stdAssertion,
          new DefaultSignServiceContext("id"));
    }).isInstanceOf(CertificateException.class);

    Mockito.when(holder.getEncoded()).thenThrow(IOException.class);

    assertThatThrownBy(() -> {
      handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, CertificateType.PKC, null,
              TestData.defaultAttributeMappings),
          TestData.stdAssertion,
          new DefaultSignServiceContext("id"));
    }).isInstanceOf(CertificateException.class)
        .hasMessage("Failed to decode issued X509 certificate");
  }

  @Test
  public void testSupports() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getClientIpAddress()).thenReturn("227.123.34.21");
    Mockito.when(request.getServerServletPath()).thenReturn(crlPath);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Assertions.assertFalse(defaultHandler.supports(request));

    Mockito.when(request.getMethod()).thenReturn("GET");
    Assertions.assertTrue(defaultHandler.supports(request));

    Mockito.when(request.getServerServletPath()).thenReturn("/other/path.crl");
    Assertions.assertFalse(defaultHandler.supports(request));
  }

  @Test
  public void testGetResource() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getClientIpAddress()).thenReturn("227.123.34.21");
    Mockito.when(request.getServerServletPath()).thenReturn(crlPath);
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpBodyAction action = defaultHandler.getResource(request);

    Assertions.assertTrue(action.getContents().length > 0);
  }

  @Test
  public void testGetResourceError() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getClientIpAddress()).thenReturn("227.123.34.21");
    Mockito.when(request.getServerServletPath()).thenReturn(crlPath);
    Mockito.when(request.getMethod()).thenReturn("POST");

    assertThatThrownBy(() -> {
      defaultHandler.getResource(request);
    }).isInstanceOf(IOException.class)
        .hasMessage("Invalid call");
  }

  private SignRequestMessage getSignRequest(final String signatureAlgorithm, final CertificateType certType,
      final String profile, final List<CertificateAttributeMapping> attributeMappings) {

    final SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    final SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    final SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(certificateRequirements.getCertificateType()).thenReturn(certType);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(profile);
    when(certificateRequirements.getAttributeMappings()).thenReturn(attributeMappings);

    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn("client");
    return signRequestMessage;
  }

  static class TestData {

    static IdentityAssertion stdAssertion = getTestAssertion();
    static List<CertificateAttributeMapping> defaultAttributeMappings = getDefaultAttributeMappings(false, false);
    static List<CertificateAttributeMapping> sanAttributeMappings = getDefaultAttributeMappings(true, false);
    static List<CertificateAttributeMapping> sdaAttributeMappings = getDefaultAttributeMappings(false, true);
    static List<CertificateAttributeMapping> allAttributeMappings = getDefaultAttributeMappings(true, true);

    private static List<CertificateAttributeMapping> getDefaultAttributeMappings(final boolean san, final boolean sda) {
      final List<CertificateAttributeMapping> attrMapList = new ArrayList<>();
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

    private static CertificateAttributeMapping getMapping(final String identifier,
        final CertificateAttributeType attributeType,
        final String friendlyName,
        final boolean required, final String defaultVal, final String[] sourceIdArray) {
      final DefaultCertificateAttributeMapping mapping = new DefaultCertificateAttributeMapping();
      final DefaultRequestedCertificateAttribute destAttr = new DefaultRequestedCertificateAttribute(
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
      final IdentityAssertion assertion = mock(IdentityAssertion.class);
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

    private static IdentityAttribute<?> getMockAttr(final String oidString, final String value,
        final String friendlyName) {
      return new StringSamlIdentityAttribute("urn:oid:" + oidString, friendlyName, value);
    }

  }

  @Data
  static class MappedAttrSouce implements IdentityAttributeIdentifier {

    private static final long serialVersionUID = 1201012063745204703L;

    public MappedAttrSouce(final String identifier) {
      this.identifier = identifier;
    }

    String scheme;
    String identifier;
    String friendlyName;
  }

}