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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Optional;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Test;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultParameter;
import se.swedenconnect.signservice.certificate.base.configuration.impl.KeyAndCertModuleDefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.DefaultSignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.base.utils.TestUtils;
import se.swedenconnect.signservice.certificate.base.utils.X509DnNameType;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.impl.DefaultSignServiceContext;

/**
 * Testing the abstract key and certificate handler
 */
@Slf4j
class AbstractKeyAndCertificateHandlerTest {

  @Test
  void keyAndCertHandlerTests() throws Exception {
    log.info("Testing Key and Certificate Handler");
    SignServiceSigningKeyProvider keyProvider = new DefaultSignServiceSigningKeyProvider(2048, 10,
      new ECGenParameterSpec("P-256"));
    DefaultConfiguration configuration = new KeyAndCertModuleDefaultConfiguration();
    KeyAndCertificateHandler keyAndCertificateHandler = new TestKeyAndCertificateHandler(
      keyProvider, configuration, AlgorithmRegistrySingleton.getInstance());
    log.info("Created key and certificate handler instance");

    assertEquals("test-key-cert-handler", keyAndCertificateHandler.getName());
    log.info("Name of instance is: ", keyAndCertificateHandler.getName());

    keyAndCertificateHandler.checkRequirements(
      getSignRequest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, "client1", CertificateType.PKC, null),
      new DefaultSignServiceContext("test-context"));
    log.info("Good checkRequirements call passed (default algorithm, default cert type)");

    testErrorRequirements(
      keyAndCertificateHandler,
      XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
      CertificateType.QC_SSCD,
      "client1",
      InvalidRequestException.class
    );
    testErrorRequirements(
      keyAndCertificateHandler,
      MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256,
      CertificateType.PKC, "client1",
      InvalidRequestException.class
    );
    testErrorRequirements(
      keyAndCertificateHandler,
      XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
      CertificateType.PKC, null,
      InvalidRequestException.class
    );
    testErrorRequirements(
      keyAndCertificateHandler,
      null,
      CertificateType.PKC, "client1",
      InvalidRequestException.class
    );
    testErrorRequirements(
      keyAndCertificateHandler,
      XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
      null, "client1",
      InvalidRequestException.class
    );

    // Set default configuraiton values
    configuration.put(DefaultParameter.signatureAlgorithm.getParameterName(),
      XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    configuration.put(DefaultParameter.certificateType.getParameterName(), CertificateType.PKC, "client1");

    keyAndCertificateHandler.checkRequirements(
      getSignRequest(null, "client1", null, null),
      new DefaultSignServiceContext("test-context"));
    log.info("Good checkRequirements call passed (ECDSA_SHA256, PKC)");

    testErrorRequirements(
      keyAndCertificateHandler,
      null,
      null, "client2",
      InvalidRequestException.class
    );

    IdentityAssertion assertion = getTestAssertion();

    // Test getting keys and cert
    testKeyAndCertGen(
      keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, "client1", null, null,
      assertion, null
    );
    testKeyAndCertGen(
      keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, "client1", null, null,
      assertion, null
    );
    testKeyAndCertGen(
      keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, "client2", null, null,
      assertion, NullPointerException.class
    );
    testKeyAndCertGen(
      keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, "client1", CertificateType.QC, null,
      assertion, CertificateException.class
    );
    testKeyAndCertGen(
      keyAndCertificateHandler, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384, "client1", CertificateType.PKC, null,
      assertion, null
    );
  }

  private void testKeyAndCertGen(KeyAndCertificateHandler keyAndCertificateHandler, String alorithm, String clientId,
    CertificateType certType, String profile, IdentityAssertion assertion, Class<? extends Exception> exceptionClass)
    throws Exception {
    if (exceptionClass == null) {
      PkiCredential pkiCredential = keyAndCertificateHandler.generateSigningCredential(
        getSignRequest(alorithm, clientId, certType, profile), assertion, new DefaultSignServiceContext("test-context")
      );
      assertDoesNotThrow(() -> pkiCredential.getCertificate().verify(pkiCredential.getPublicKey()));
      log.info("Successfully issued key and certificate for algorithm {}, certtype {} and profile {}", alorithm,
        certType, profile);
      log.info("Issued certificate\n{}", TestUtils.base64Print(pkiCredential.getCertificate().getEncoded(), 80));
      return;
    }

    Exception exception = assertThrows(exceptionClass, () -> keyAndCertificateHandler.generateSigningCredential(
      getSignRequest(alorithm, clientId, certType, profile), assertion, new DefaultSignServiceContext("test-context")
    ));
    log.info("Caught expected exception for algorithm {}, certtype {} and profile {}", alorithm, certType, profile);
    log.info("Caught exception: {}", exception.toString());
  }

  private IdentityAssertion getTestAssertion() {
    IdentityAssertion assertion = mock(IdentityAssertion.class);
    when(assertion.getIdentityAttributes()).thenReturn(List.of(
      getMockAttr(X509DnNameType.GivenName.getOidString(), "Nisse"),
      getMockAttr(X509DnNameType.Surename.getOidString(), "Hult"),
      getMockAttr(X509DnNameType.SerialNumber.getOidString(), "1234567890"),
      getMockAttr(X509DnNameType.Country.getOidString(), "SE"),
      getMockAttr(X509DnNameType.CN.getOidString(), "Nisse Hult")
    ));
    return assertion;
  }

  private IdentityAttribute<?> getMockAttr(String oidString, String value) {
    return new StringSamlIdentityAttribute(oidString, null, value);
  }

  private void testErrorRequirements(KeyAndCertificateHandler keyAndCertificateHandler, String algorithm,
    CertificateType certType, String clientId, Class<? extends Exception> exceptionClass) {
    Exception exception = assertThrows(exceptionClass, () -> keyAndCertificateHandler.checkRequirements(
      getSignRequest(algorithm, clientId, certType, null), new DefaultSignServiceContext("test-context")));
    log.info("Test with signature algorithm: " + algorithm + " and certificate type: " + certType
      + "Resulted in exception: " + exception.toString());
  }

  private SignRequestMessage getSignRequest(String signatureAlgorithm, String clientId,
    CertificateType certType, String profile) {
    SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(certificateRequirements.getCertificateType()).thenReturn(certType);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(profile);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn(clientId);
    return signRequestMessage;
  }

  /**
   * Provides a test implementation of the abstract key and certificate handler
   */
  class TestKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

    /** {@inheritDoc} */
    public TestKeyAndCertificateHandler(
      @NonNull SignServiceSigningKeyProvider signingKeyProvider,
      @NonNull DefaultConfiguration defaultConfiguration,
      @NonNull AlgorithmRegistry algorithmRegistry) {
      super(signingKeyProvider, defaultConfiguration, algorithmRegistry);
    }

    /** {@inheritDoc} */
    @Override protected void specificRequirementTests(SignRequestMessage signRequest,
      SignServiceContext context) throws InvalidRequestException {
    }

    /** {@inheritDoc} */
    @Override protected X509Certificate obtainSigningCertificate(PkiCredential signingKeyPair, SignRequestMessage signRequest,
      IdentityAssertion assertion, SignServiceContext context) throws CertificateException {

      CertificateType certificateType = Optional.ofNullable(context.get(DefaultParameter.certificateType.getParameterName(),
        CertificateType.class)).orElseThrow(() -> new NullPointerException("Null certificate Type is not allowed"));
      String profile = context.get(DefaultParameter.certificateProfile.getParameterName(), String.class);

      try {
        isCertificateTypeSupported(certificateType, profile);
      }
      catch (InvalidRequestException e) {
        throw new CertificateException(e.getMessage());
      }

      TestUtils.DNBuilder dnBuilder = TestUtils.DNBuilder.getInstance();
      List<IdentityAttribute<?>> identityAttributes = assertion.getIdentityAttributes();
      for (IdentityAttribute<?> attribute : identityAttributes) {
        String identifier = attribute.getIdentifier();
        X509DnNameType nameType = X509DnNameType.getNameTypeForOid(identifier);
        if (nameType != null) {
          Object value = attribute.getValue();
          if (value != null && value instanceof String) {
            dnBuilder.attr(nameType, (String) value);
          }
        }
      }
      if (dnBuilder.getSize() == 0) {
        throw new CertificateException("No subject name provided");
      }

      String signatureAlgorithmId = signRequest.getSignatureRequirements().getSignatureAlgorithm();
      SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(signatureAlgorithmId);
      String certSigningAlgoJcaName;
      switch (signatureAlgorithm.getKeyType()) {
      case "RSA":
        certSigningAlgoJcaName = ((SignatureAlgorithm) algorithmRegistry.getAlgorithm(
          XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)).getJcaName();
        break;
      case "EC":
        certSigningAlgoJcaName = ((SignatureAlgorithm) algorithmRegistry.getAlgorithm(
          XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256)).getJcaName();
        break;
      default:
        throw new CertificateException("Unsupported signature algorithm key type");
      }

      try {
        return TestUtils.generateCertificate(signingKeyPair, dnBuilder.build(), certSigningAlgoJcaName);
      }
      catch (Exception e) {
        throw new CertificateException("Unable to generate certificate", e);
      }
    }

    /** {@inheritDoc} */
    @Override protected void isCertificateTypeSupported(@NonNull CertificateType certificateType,
      String certificateProfile) throws InvalidRequestException {
      if (!certificateType.equals(CertificateType.PKC)) {
        throw new InvalidRequestException("Unsupported certificate type " + certificateType.getType());
      }
    }

    /** {@inheritDoc} */
    @Override public String getName() {
      return "test-key-cert-handler";
    }
  }

}