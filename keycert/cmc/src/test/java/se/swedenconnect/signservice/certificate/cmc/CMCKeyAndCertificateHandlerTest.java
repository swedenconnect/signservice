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

package se.swedenconnect.signservice.certificate.cmc;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.SigningKeyUsageDirective;
import se.swedenconnect.signservice.certificate.cmc.testutils.CMCApiFactory;
import se.swedenconnect.signservice.certificate.cmc.testutils.TestCMCHttpConnector;
import se.swedenconnect.signservice.certificate.cmc.testutils.TestCredentials;
import se.swedenconnect.signservice.certificate.cmc.testutils.ca.BadCAService;
import se.swedenconnect.signservice.certificate.cmc.testutils.ca.TestCA;
import se.swedenconnect.signservice.certificate.cmc.testutils.ca.TestCAHolder;
import se.swedenconnect.signservice.certificate.cmc.testutils.ca.TestServices;
import se.swedenconnect.signservice.context.DefaultSignServiceContext;
import se.swedenconnect.signservice.context.SignServiceContext;
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

/**
 * Tests for CMC based certificate issuance
 */
@Slf4j
class CMCKeyAndCertificateHandlerTest {

  static PkiCredentialContainer keyProvider;
  static AlgorithmRegistry algorithmRegistry;
  static AttributeMapper attributeMapper;

  @BeforeAll
  static void init() throws Exception{
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    keyProvider = new SoftPkiCredentialContainer("BC", "Test1234");

    algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    attributeMapper = new DefaultAttributeMapper(
        (attributeType, ref, value) -> attributeType.equals(CertificateAttributeType.RDN) && ref.equalsIgnoreCase(
            CertAttributes.C.getId())
            && value.equalsIgnoreCase("SE"));
    TestServices.addCa(TestCA.INSTANCE1);
    TestServices.addCa(TestCA.RSA_PSS_CA);
    TestServices.addCa(TestCA.ECDSA_CA);
  }

  Function<X509CertificateHolder, X509Certificate> mapCert = h -> {
    try {
      return X509Utils.decodeCertificate(h.getEncoded());
    }
    catch (final CertificateException | IOException e) {
      throw new SecurityException("Failed to decode certificate", e);
    }
  };

  private SignServiceCMCClient getCMCClient(CAService caService) throws Exception {
    RemoteCaInformation caInformation = RemoteCaInformation.builder()
        .caAlgorithm(caService.getCaAlgorithm())
        .caCertificateChain(caService.getCACertificateChain().stream().map(mapCert).collect(Collectors.toList()))
        .ocspResponderUrl(caService.getOCSPResponderURL())
        .crlDpUrls(caService.getCrlDpURLs())
        .build();

    SignServiceCMCClient cmcClient = new SignServiceCMCClient("http://example.com/test",
        new BasicCredential(TestCredentials.cMCClientSignerCertificate, TestCredentials.privateCMCClientSignerECKey),
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        TestCredentials.cMCCaSignerCertificate, caInformation);
    return cmcClient;
  }

  @Test
  void obtainSigningCertificate() throws Exception {

    TestCAHolder caHolder = TestServices.getTestCAs().get(TestCA.INSTANCE1);
    SignServiceCMCClient rsaCaCmcClient = getCMCClient(caHolder.getCscaService());
    rsaCaCmcClient
        .setCmcClientHttpConnector(new TestCMCHttpConnector(CMCApiFactory.getCMCApi(caHolder.getCscaService())));
    CMCKeyAndCertificateHandler keyAndCertificateHandler = new CMCKeyAndCertificateHandler(
        keyProvider, AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES,
      attributeMapper, algorithmRegistry, rsaCaCmcClient);
    rsaCaCmcClient
        .setProfileConfiguration(CertificateProfileConfiguration.builder()
            .policies(List.of("1.2.3.4.5.6.7.8.9"))
            .extendedKeyUsageCritical(true)
            .extendedKeyUsages(List.of("1.2.3.4.5.6.7", "2.3.4.5.6.7.8"))
            .usageDirective(SigningKeyUsageDirective.builder().encrypt(true).excludeNonRepudiation(true).build())
            .build());
    log.info("Created CMC key and certificate handler");

    CMCClient badRsaCaCmcClient = getCMCClient(caHolder.getCscaService());
    badRsaCaCmcClient
        .setCmcClientHttpConnector(new TestCMCHttpConnector(CMCApiFactory.getBadCMCApi(caHolder.getCscaService())));
    CMCKeyAndCertificateHandler badKeyAndCertificateHandler = new CMCKeyAndCertificateHandler(
      keyProvider, AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES, attributeMapper, algorithmRegistry, badRsaCaCmcClient);
    log.info("Created bad CMC key and certificate handler");

    TestCAHolder rsaPssCaHolder = TestServices.getTestCAs().get(TestCA.RSA_PSS_CA);
    CMCClient rsaPssCaCmcClient = getCMCClient(rsaPssCaHolder.getCscaService());
    rsaPssCaCmcClient
        .setCmcClientHttpConnector(new TestCMCHttpConnector(CMCApiFactory.getCMCApi(rsaPssCaHolder.getCscaService())));
    CMCKeyAndCertificateHandler rsaPssCaKeyAndCertificateHandler = new CMCKeyAndCertificateHandler(
      keyProvider, null, attributeMapper, null, rsaPssCaCmcClient);
    log.info("Created RSA PSS CA CMC key and certificate handler");

    TestCAHolder ecCaHolder = TestServices.getTestCAs().get(TestCA.ECDSA_CA);
    CMCClient ecCaCmcClient = getCMCClient(ecCaHolder.getCscaService());
    ecCaCmcClient
        .setCmcClientHttpConnector(new TestCMCHttpConnector(CMCApiFactory.getCMCApi(ecCaHolder.getCscaService())));
    CMCKeyAndCertificateHandler ecCaKeyAndCertificateHandler = new CMCKeyAndCertificateHandler(
      keyProvider, AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES, attributeMapper, algorithmRegistry, ecCaCmcClient);
    log.info("Created ECDSA CA CMC key and certificate handler");

    CMCClient badCaCmcClient = getCMCClient(ecCaHolder.getCscaService());
    badCaCmcClient.setCmcClientHttpConnector(new TestCMCHttpConnector(CMCApiFactory.getCMCApi(
        new BadCAService(TestServices.getTestCAs().get(TestCA.INSTANCE1).getCscaService()))));
    CMCKeyAndCertificateHandler badCaKeyAndCertificateHandler = new CMCKeyAndCertificateHandler(
      keyProvider, AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES, attributeMapper, algorithmRegistry, badCaCmcClient);
    log.info("Created ECDSA CA CMC key and certificate handler");

    keyAndCertificateHandler.checkRequirements(getCheckRequirementsRequest(CertificateType.PKC, "client-01"), null);
    log.info("Testing support for PKC certificates successful");
    InvalidRequestException e1 = assertThrows(InvalidRequestException.class,
        () -> keyAndCertificateHandler.checkRequirements(getCheckRequirementsRequest(CertificateType.QC, "client-01"),
            null));
    log.info("Caught exception when checking requirements: {}", e1.toString());

    testKeyAndCertGeneration("Normal ECDSA test - RSA CA",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal ECDSA test - RSA-PSS CA",
        rsaPssCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal ECDSA test - EC CA",
        ecCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal RSA test",
        ecCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("Normal RSA-PSS test",
        ecCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, null);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        ecCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.allAttributeMappings, null);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        ecCaKeyAndCertificateHandler, "Bad algorithm",
        "client01", CertificateType.PKC,
        null, TestData.allAttributeMappings, InvalidRequestException.class);

    testKeyAndCertGeneration("SAN and Subj Directory Attributes test",
        keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.QC,
        null, TestData.allAttributeMappings, InvalidRequestException.class);

    testKeyAndCertGeneration("Bad CMC Request validator",
        badKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, CertificateException.class);

    testKeyAndCertGeneration("Bad CMC Request validator",
        badCaKeyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.defaultAttributeMappings, CertificateException.class);

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

      X509Certificate certificate = pkiCredential.getCertificate();
      log.info("Issued certificate from CA:\n{}\n{}",
          new PrintCertificate(certificate).toString(true, true, true),
          new PrintCertificate(certificate).toPEM());

      X509CertificateHolder certHolder = new JcaX509CertificateHolder(certificate);
      Assertions.assertNotNull(certHolder.getExtension(Extension.authorityKeyIdentifier));
      Assertions.assertNotNull(certHolder.getExtension(Extension.subjectKeyIdentifier));
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