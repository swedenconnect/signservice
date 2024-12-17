/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.certificate.simple.ca;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

/**
 * Test cases for DefaultSelfSignedCaCertificateGenerator.
 */
@Slf4j
class DefaultSelfSignedCaCertificateGeneratorTest {

  private static SelfSignedCaCertificateGenerator generator;
  private static PkiCredentialContainer userKeyProvider;
  private static CertNameModel<?> caNameModel;

  @BeforeAll
  public static void init() throws KeyStoreException {
    generator = new DefaultSelfSignedCaCertificateGenerator();
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    userKeyProvider = new SoftPkiCredentialContainer("BC", "Test1234");

    caNameModel = new ExplicitCertNameModel(List.of(
        new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
        new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
        new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
        new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890")));
  }

  @Test
  public void testEcdsa() throws Exception {
    final X509Certificate caCertificate = generator.generate(userKeyProvider.getCredential(userKeyProvider.generateCredential(
        KeyGenType.EC_P256)),
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, Duration.ofDays(365)), caNameModel);
    log.info("Successfully created CA Certificate:\n{}",
        (new PrintCertificate(caCertificate)).toString(true, true, true));
  }

  @Test
  public void testRsa() throws Exception {
    final X509Certificate caCertificate = generator.generate(userKeyProvider.getCredential(userKeyProvider.generateCredential(
        KeyGenType.RSA_3072)),
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, Duration.ofDays(365)), caNameModel);
    log.info("Successfully created CA Certificate:\n{}",
        (new PrintCertificate(caCertificate)).toString(true, true, true));
  }

  @Test
  public void testRsaKeyWithEcAlgo() throws Exception {
    assertThatThrownBy(() -> {
      generator.generate(userKeyProvider.getCredential(userKeyProvider.generateCredential(
          KeyGenType.RSA_3072)),
          new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, Duration.ofDays(365)), caNameModel);
    }).isInstanceOf(CertificateException.class);
  }

}
