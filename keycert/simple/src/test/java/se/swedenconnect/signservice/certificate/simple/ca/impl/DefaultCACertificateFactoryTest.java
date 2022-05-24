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
package se.swedenconnect.signservice.certificate.simple.ca.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.DefaultSignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.simple.ca.CACertificateFactory;

import java.security.KeyPair;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CA certificate factory test
 */
@Slf4j
class DefaultCACertificateFactoryTest {

  private static CACertificateFactory caCertificateFactory;

  @BeforeAll
  private static void init() {
    caCertificateFactory = new DefaultCACertificateFactory();
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void getCACertificate() throws Exception {
    SignServiceSigningKeyProvider keyProvider = new DefaultSignServiceSigningKeyProvider(2048, 5,
      new ECGenParameterSpec("P-256"));

    ExplicitCertNameModel caNameModel = new ExplicitCertNameModel(List.of(
      new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
      new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
      new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
      new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890")
    ));

    testCACertFactory(
      "EC key pair test case",
      keyProvider.getSigningKeyPair("EC"),
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
      caNameModel, null
    );
    testCACertFactory(
      "RSA key pair test case",
      keyProvider.getSigningKeyPair("RSA"),
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, 10),
      caNameModel, null
    );
    testCACertFactory(
      "RSA key with EC algorithm test case",
      keyProvider.getSigningKeyPair("RSA"),
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
      caNameModel, CertificateIssuanceException.class
    );
    testCACertFactory(
      "Null key pair test case",
      null,
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
      caNameModel, NullPointerException.class
    );
    testCACertFactory(
      "Null cert issuer model",
      keyProvider.getSigningKeyPair("EC"),
      null,
      caNameModel, NullPointerException.class
    );
    testCACertFactory(
      "Null CA name model",
      keyProvider.getSigningKeyPair("EC"),
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
      null, NullPointerException.class
    );

  }

  private void testCACertFactory(String desc, KeyPair keyPair, CertificateIssuerModel certificateIssuerModel,
    ExplicitCertNameModel caNameModel, Class<? extends Exception> exceptionClass) throws Exception {
    log.info(desc);
    if (exceptionClass == null) {
      X509CertificateHolder caCertificate = caCertificateFactory.getCACertificate(certificateIssuerModel, caNameModel,
        keyPair);
      log.info("Successfully created CA Certificate:\n{}",
        (new PrintCertificate(caCertificate)).toString(true, true, true));
      return;
    }

    Exception ex = assertThrows(exceptionClass,
      () -> caCertificateFactory.getCACertificate(certificateIssuerModel, caNameModel, keyPair));
    log.info("Successfully caught exception at CA certificate creation: {}", ex.toString());
  }
}