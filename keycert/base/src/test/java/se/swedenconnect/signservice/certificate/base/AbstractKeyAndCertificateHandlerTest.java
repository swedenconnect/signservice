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
package se.swedenconnect.signservice.certificate.base;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.Serializable;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingException;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.base.utils.TestUtils;
import se.swedenconnect.signservice.certificate.base.utils.X509DnNameType;
import se.swedenconnect.signservice.certificate.keyprovider.InMemoryECKeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.OnDemandInMemoryRSAKeyProvider;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.RequestedCertificateAttribute;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.impl.DefaultSignServiceContext;

/**
 * Tests for AbstractKeyAndCertificateHandler and AbstractCaEngineKeyAndCertificateHandler.
 */
@Slf4j
public class AbstractKeyAndCertificateHandlerTest {

  final KeyAndCertificateHandler handler;

  final SignServiceContext mockedContext;

  public AbstractKeyAndCertificateHandlerTest() {
    this.handler = new TestKeyAndCertificateHandler(
        Arrays.asList(
            new OnDemandInMemoryRSAKeyProvider(2048), new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))),
        AlgorithmRegistrySingleton.getInstance());

    this.mockedContext = Mockito.mock(SignServiceContext.class);
  }

  @Test
  public void testNoProviders() {
    assertThatThrownBy(() -> {
      new TestKeyAndCertificateHandler(Collections.emptyList());
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("At least one key provider must be configured");
  }

  @Test
  public void testCheckRequirements() throws InvalidRequestException {
    final KeyAndCertificateHandler keyAndCertificateHandler = new TestKeyAndCertificateHandler(
        Arrays.asList(
            new OnDemandInMemoryRSAKeyProvider(2048), new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))));
    log.info("Created key and certificate handler instance");

    keyAndCertificateHandler.checkRequirements(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null),
        this.mockedContext);

    keyAndCertificateHandler.checkRequirements(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, null, null),
        this.mockedContext);
  }

  @Test
  public void testCheckRequirementsUnsupportedKeyType() {

    final TestKeyAndCertificateHandler handler = new TestKeyAndCertificateHandler(
        Arrays.asList(new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))));

    assertThatThrownBy(() -> {
      handler.checkRequirements(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, CertificateType.PKC, null),
          this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessageContaining("Unsupported key type");
  }

  @Test
  public void testCheckRequirementsUnsupportedCertificateType() {

    assertThatThrownBy(() -> {
      this.handler.checkRequirements(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.QC_SSCD, null),
          this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Handler does not support certificate type " + CertificateType.QC_SSCD);

    final TestKeyAndCertificateHandler handler = new TestKeyAndCertificateHandler(Arrays
        .asList(new OnDemandInMemoryRSAKeyProvider(2048), new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))));
    handler.setCaCertificateType(CertificateType.QC);

    assertThatThrownBy(() -> {
      handler.checkRequirements(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null),
          this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Handler does not support certificate type " + CertificateType.PKC);
  }

  @Test
  public void testCheckRequirementsNotSigningAlgo() {
    assertThatThrownBy(() -> {
      this.handler.checkRequirements(
          this.getSignRequest(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, CertificateType.PKC, null),
          this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Requested signature algorithm is not a valid signature algorithm");
  }

  @Test
  public void testCheckRequirementsUnsupportedAlgo() {
    assertThatThrownBy(() -> {
      this.handler.checkRequirements(
          this.getSignRequest("unsupported-algo", CertificateType.PKC, null), this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessageContaining("Unsupported signature algorithm:");
  }

  @Test
  public void testCheckRequirementsMissingAlgo() {
    assertThatThrownBy(() -> {
      this.handler.checkRequirements(
          this.getSignRequest(null, CertificateType.PKC, null), this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Signature algorithm must be set in sign request");
  }

  @Test
  public void testCheckRequirementsUnsupportedProfile() {
    assertThatThrownBy(() -> {
      this.handler.checkRequirements(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, "dummyProfile"),
          this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Certificate profile is not supported");
  }

  @Test
  public void testCheckRequirementsMissingCertReqs() {
    final SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    final SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getClientId()).thenReturn("clientId");

    assertThatThrownBy(() -> {
      this.handler.checkRequirements(signRequestMessage, this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Missing certificate requirements");
  }

  @Test
  public void testCheckRequirementsMissingAttributeMappings() {
    final SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    final SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    final SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    when(certificateRequirements.getCertificateType()).thenReturn(CertificateType.PKC);
    when(certificateRequirements.getAttributeMappings()).thenReturn(null);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(null);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn("clientId");

    assertThatThrownBy(() -> {
      this.handler.checkRequirements(signRequestMessage, this.mockedContext);
    }).isInstanceOf(InvalidRequestException.class)
        .hasMessage("Missing attribute mappings in sign request");
  }

  @Test
  public void testKeyAndCertGenRsa() throws Exception {
    final IdentityAssertion assertion = this.getTestAssertion();

    final PkiCredential credential = this.handler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, null, null), assertion,
        new DefaultSignServiceContext("ctx"));
    assertDoesNotThrow(() -> credential.getCertificate().verify(credential.getPublicKey()));

    final PkiCredential credential2 = this.handler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384, null, null), assertion,
        new DefaultSignServiceContext("ctx"));
    assertDoesNotThrow(() -> credential2.getCertificate().verify(credential2.getPublicKey()));
  }

  @Test
  public void testKeyAndCertGenEcdsa() throws Exception {
    final IdentityAssertion assertion = this.getTestAssertion();

    final PkiCredential credential = this.handler.generateSigningCredential(
        this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null), assertion,
        new DefaultSignServiceContext("ctx"));
    assertDoesNotThrow(() -> credential.getCertificate().verify(credential.getPublicKey()));
  }

  @Test
  public void testKeyAndCertGenMappingError() throws Exception {
    final IdentityAssertion assertion = this.getTestAssertion();

    final SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    final SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    final SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    when(certificateRequirements.getCertificateType()).thenReturn(CertificateType.PKC);
    when(certificateRequirements.getAttributeMappings()).thenReturn(null);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(null);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn("clientId");

    assertThatThrownBy(() -> {
      this.handler.generateSigningCredential(signRequestMessage, assertion, new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(CertificateException.class)
        .hasMessage("Attribute mapping failed")
        .getCause()
        .isInstanceOf(AttributeMappingException.class);
  }

  @Test
  public void testInvalidAssertion() throws Exception {

    final IdentityAssertion assertion = mock(IdentityAssertion.class);
    when(assertion.getIdentifier()).thenReturn(null);
    when(assertion.getIdentityAttributes()).thenReturn(null);

    assertThatThrownBy(() -> {
      this.handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null), assertion, new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Assertion identifier must be set");

    when(assertion.getIdentifier()).thenReturn("id");
    when(assertion.getAuthnContext()).thenReturn(null);

    assertThatThrownBy(() -> {
      this.handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null), assertion, new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Assertion authentication LoA identifier must be present");

    final AuthnContextIdentifier aci = mock(AuthnContextIdentifier.class);
    when(aci.getIdentifier()).thenReturn("http://id.elegnamnden.se/loa/1.0/loa3");
    when(assertion.getAuthnContext()).thenReturn(aci);

    when(assertion.getIssuer()).thenReturn(null);

    assertThatThrownBy(() -> {
      this.handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null), assertion, new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Assertion issuer must not be present");

    when(assertion.getIssuer()).thenReturn("https://www.idp.com");
    when(assertion.getAuthnInstant()).thenReturn(null);

    assertThatThrownBy(() -> {
      this.handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, CertificateType.PKC, null), assertion, new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing authentication instant from assertion");
  }

  @Test
  public void testKeyAndCertMissingKeyProvider() throws Exception {

    final TestKeyAndCertificateHandler handler = new TestKeyAndCertificateHandler(
        Arrays.asList(new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))));

    final IdentityAssertion assertion = this.getTestAssertion();

    assertThatThrownBy(() -> {
      handler.generateSigningCredential(
          this.getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, null, null), assertion,
          new DefaultSignServiceContext("ctx"));
    }).isInstanceOf(KeyException.class)
        .hasMessageContaining("Unsupported key type: ");

  }

  private IdentityAssertion getTestAssertion() {
    final IdentityAssertion assertion = mock(IdentityAssertion.class);
    final AuthnContextIdentifier aci = mock(AuthnContextIdentifier.class);

    when(aci.getIdentifier()).thenReturn("http://id.elegnamnden.se/loa/1.0/loa3");
    when(assertion.getAuthnContext()).thenReturn(aci);
    when(assertion.getIdentifier()).thenReturn("123");
    when(assertion.getIssuer()).thenReturn("https://www.idp.com");
    when(assertion.getAuthnInstant()).thenReturn(Instant.now());
    when(assertion.getIdentityAttributes()).thenReturn(List.of(
        this.getMockAttr("urn:oid:2.5.4.42", "Nisse"),
        this.getMockAttr("urn:oid:2.5.4.4", "Hult"),
        this.getMockAttr("urn:oid:1.2.752.29.4.13", "1234567890"),
        this.getMockAttr("urn:oid:2.5.4.6", "SE"),
        this.getMockAttr("urn:oid:0.9.2342.19200300.100.1.3", "nisse.hult@example.com"),
        this.getMockAttr("urn:oid:2.16.840.1.113730.3.1.241", "Nisse Hult"),
        this.getMockAttr("urn:oid:1.3.6.1.5.5.7.9.3", "M")));
    return assertion;
  }

  private IdentityAttribute<?> getMockAttr(final String oidString, final String value) {
    return new StringSamlIdentityAttribute(oidString, null, value);
  }

  private SignRequestMessage getSignRequest(final String signatureAlgorithm,
      final CertificateType certType, final String profile) {

    final SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    final SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    final SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(certificateRequirements.getCertificateType()).thenReturn(certType);
    when(certificateRequirements.getAttributeMappings()).thenReturn(this.getCertificateAttributeMappings(
        new Object[][] {
            { CertificateAttributeType.RDN, "urn:oid:2.5.4.42", X509DnNameType.GivenName.getOidString() },
            { CertificateAttributeType.RDN, "urn:oid:2.5.4.4", X509DnNameType.Surename.getOidString() },
            { CertificateAttributeType.RDN, "urn:oid:1.2.752.29.4.13", X509DnNameType.SerialNumber.getOidString() },
            { CertificateAttributeType.RDN, "urn:oid:2.5.4.6", X509DnNameType.Country.getOidString() },
            { CertificateAttributeType.SAN, "urn:oid:0.9.2342.19200300.100.1.3", "1" },
            { CertificateAttributeType.RDN, "urn:oid:2.16.840.1.113730.3.1.241", X509DnNameType.CN.getOidString() },
            { CertificateAttributeType.SDA, "urn:oid:1.3.6.1.5.5.7.9.3", "1.3.6.1.5.5.7.9.3" }
        }));
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(profile);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn("clientId");
    return signRequestMessage;
  }

  private List<CertificateAttributeMapping> getCertificateAttributeMappings(final Object[][] mappings) {
    final List<CertificateAttributeMapping> cam = new ArrayList<>();
    for (final Object[] m : mappings) {
      cam.add(new CertificateAttributeMapping() {
        private static final long serialVersionUID = -3840907348050216199L;

        @Override
        public List<IdentityAttributeIdentifier> getSources() {
          return Arrays.asList(new IdentityAttributeIdentifier() {
            private static final long serialVersionUID = -6428145705416252481L;

            @Override
            public String getScheme() {
              return "SAML";
            }

            @Override
            public String getIdentifier() {
              return (String) m[1];
            }

            @Override
            public String getFriendlyName() {
              return null;
            }

          });
        }

        @Override
        public RequestedCertificateAttribute getDestination() {
          return new RequestedCertificateAttribute() {

            private static final long serialVersionUID = 598969777187387281L;

            @Override
            public CertificateAttributeType getType() {
              return (CertificateAttributeType) m[0];
            }

            @Override
            public String getIdentifier() {
              return (String) m[2];
            }

            @Override
            public String getFriendlyName() {
              return null;
            }

            @Override
            public String getDefaultValue() {
              return null;
            }

            @Override
            public boolean isRequired() {
              return false;
            }

          };
        }

      });
    }
    return cam;
  }

  /**
   * Provides a test implementation of the abstract key and certificate handler
   */
  class TestKeyAndCertificateHandler extends AbstractCaEngineKeyAndCertificateHandler {

    public TestKeyAndCertificateHandler(
        @Nonnull final List<KeyProvider> keyProviders) {
      super(keyProviders, new DefaultAttributeMapper((p1, p2, p3) -> false));
    }

    public TestKeyAndCertificateHandler(
        @Nonnull final List<KeyProvider> keyProviders,
        @Nonnull final AlgorithmRegistry algorithmRegistry) {
      super(keyProviders, new DefaultAttributeMapper((p1, p2, p3) -> false), algorithmRegistry);
    }

    @Override
    protected List<X509Certificate> issueSigningCertificateChain(@Nonnull final PkiCredential signingKeyPair,
        @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
        @Nonnull final List<AttributeMappingData> certAttributes, @Nullable final String certificateProfile,
        @Nonnull final SignServiceContext context) throws CertificateException {

      // Just for the tests ...
      context.put("signingKeyPair", new PkiCredentialWrapper(signingKeyPair));
      context.put("algorithm", signRequest.getSignatureRequirements().getSignatureAlgorithm());

      return super.issueSigningCertificateChain(signingKeyPair, signRequest, assertion, certAttributes, certificateProfile,
          context);
    }

    @Override
    protected List<X509Certificate> issueSigningCertificateChain(final CertificateModel certificateModel,
        final String certificateProfile, final SignServiceContext context) throws CertificateException {

      final PkiCredential signingKeyPair = context.get("signingKeyPair", PkiCredentialWrapper.class).getCredential();
      context.remove("signingKeyPair");

      final TestUtils.DNBuilder dnBuilder = TestUtils.DNBuilder.getInstance();
      final CertNameModel<?> cnm = certificateModel.getSubject();
      @SuppressWarnings("unchecked")
      final List<List<AttributeTypeAndValueModel>> rdnSequence =
          (List<List<AttributeTypeAndValueModel>>) cnm.getNameData();
      for (final List<AttributeTypeAndValueModel> rdnL : rdnSequence) {
        if (rdnL.isEmpty()) {
          continue;
        }
        // Only support one ...
        final X509DnNameType nameType = X509DnNameType.getNameTypeForOid(rdnL.get(0).getAttributeType().getId());
        if (nameType != null) {
          dnBuilder.attr(nameType, (String) rdnL.get(0).getValue());
        }
      }
      if (dnBuilder.getSize() == 0) {
        throw new CertificateException("No subject name provided");
      }

      final String signatureAlgorithmId = context.get("algorithm", String.class);
      final SignatureAlgorithm signatureAlgorithm =
          (SignatureAlgorithm) this.getAlgorithmRegistry().getAlgorithm(signatureAlgorithmId);
      String certSigningAlgoJcaName;
      switch (signatureAlgorithm.getKeyType()) {
      case "RSA":
        certSigningAlgoJcaName = this.getAlgorithmRegistry().getAlgorithm(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1).getJcaName();
        break;
      case "EC":
        certSigningAlgoJcaName = this.getAlgorithmRegistry().getAlgorithm(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256).getJcaName();
        break;
      default:
        throw new CertificateException("Unsupported signature algorithm key type");
      }

      try {
        return List.of(TestUtils.generateCertificate(signingKeyPair, dnBuilder.build(), certSigningAlgoJcaName));
      }
      catch (final Exception e) {
        throw new CertificateException("Unable to generate certificate", e);
      }
    }

    @Override
    protected AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> createCertificateModelBuilder(
        final PublicKey subjectPublicKey, final CertNameModel<?> subject) throws CertificateException {
      return new TestCertificateModelBuilder(subjectPublicKey, subject);
    }

    // @Override
    protected X509Certificate issueSigningCertificate2(@Nonnull final PkiCredential signingKeyPair,
        @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
        @Nonnull final List<AttributeMappingData> certAttributes, @Nullable final String certificateProfile,
        @Nonnull final SignServiceContext context) throws CertificateException {

      try {
        this.assertCertificateProfileSupported(certificateProfile);
      }
      catch (final InvalidRequestException e) {
        throw new CertificateException(e.getMessage());
      }

      final TestUtils.DNBuilder dnBuilder = TestUtils.DNBuilder.getInstance();
      final List<IdentityAttribute<?>> identityAttributes = assertion.getIdentityAttributes();
      for (final IdentityAttribute<?> attribute : identityAttributes) {
        final String identifier = attribute.getIdentifier();
        final X509DnNameType nameType = X509DnNameType.getNameTypeForOid(identifier);
        if (nameType != null) {
          final Object value = attribute.getValue();
          if (value != null && value instanceof String) {
            dnBuilder.attr(nameType, (String) value);
          }
        }
      }
      if (dnBuilder.getSize() == 0) {
        throw new CertificateException("No subject name provided");
      }

      final String signatureAlgorithmId = signRequest.getSignatureRequirements().getSignatureAlgorithm();
      final SignatureAlgorithm signatureAlgorithm =
          (SignatureAlgorithm) this.getAlgorithmRegistry().getAlgorithm(signatureAlgorithmId);
      String certSigningAlgoJcaName;
      switch (signatureAlgorithm.getKeyType()) {
      case "RSA":
        certSigningAlgoJcaName = this.getAlgorithmRegistry().getAlgorithm(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1).getJcaName();
        break;
      case "EC":
        certSigningAlgoJcaName = this.getAlgorithmRegistry().getAlgorithm(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256).getJcaName();
        break;
      default:
        throw new CertificateException("Unsupported signature algorithm key type");
      }

      try {
        return TestUtils.generateCertificate(signingKeyPair, dnBuilder.build(), certSigningAlgoJcaName);
      }
      catch (final Exception e) {
        throw new CertificateException("Unable to generate certificate", e);
      }
    }

    @Override
    protected void assertCertificateProfileSupported(final String certificateProfile) throws InvalidRequestException {
      if (StringUtils.isNotBlank(certificateProfile)) {
        throw new InvalidRequestException("Certificate profile is not supported");
      }
    }

    @Override
    public String getName() {
      return "test-key-cert-handler";
    }

  }

  private static class TestCertificateModelBuilder
      extends AbstractCertificateModelBuilder<TestCertificateModelBuilder> {

    private final PublicKey publicKey;

    public TestCertificateModelBuilder(final PublicKey publicKey, final CertNameModel<?> subject) {
      this.publicKey = publicKey;
      this.subject = subject;
    }

    @Override
    protected PublicKey getPublicKey() {
      return this.publicKey;
    }

    @Override
    protected void addKeyIdentifierExtensionsModels(List<ExtensionModel> extensionModelList) throws IOException {
    }

  }

  private static class PkiCredentialWrapper implements Serializable {
    private static final long serialVersionUID = -6232689936250396654L;

    @Getter
    private final PkiCredential credential;

    public PkiCredentialWrapper(final PkiCredential credential) {
      this.credential = credential;
    }
  }

}