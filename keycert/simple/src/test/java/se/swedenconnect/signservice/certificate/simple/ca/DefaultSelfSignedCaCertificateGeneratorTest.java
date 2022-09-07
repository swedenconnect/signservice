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
package se.swedenconnect.signservice.certificate.simple.ca;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.signservice.certificate.keyprovider.InMemoryECKeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.OnDemandInMemoryRSAKeyProvider;

/**
 * Test cases for DefaultSelfSignedCaCertificateGenerator.
 */
@Slf4j
class DefaultSelfSignedCaCertificateGeneratorTest {

  private static SelfSignedCaCertificateGenerator generator;
  private static KeyProvider rsaProvider;
  private static KeyProvider ecProvider;
  private static CertNameModel<?> caNameModel;

  @BeforeAll
  public static void init() {
    generator = new DefaultSelfSignedCaCertificateGenerator();
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    rsaProvider = new OnDemandInMemoryRSAKeyProvider(2048);
    ecProvider = new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"));

    caNameModel = new ExplicitCertNameModel(List.of(
        new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
        new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
        new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
        new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890")));
  }

  @Test
  public void testEcdsa() throws Exception {
    final X509Certificate caCertificate = generator.generate(ecProvider.getKeyPair(),
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10), caNameModel);
    log.info("Successfully created CA Certificate:\n{}",
        (new PrintCertificate(caCertificate)).toString(true, true, true));
  }

  @Test
  public void testRsa() throws Exception {
    final X509Certificate caCertificate = generator.generate(rsaProvider.getKeyPair(),
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, 10), caNameModel);
    log.info("Successfully created CA Certificate:\n{}",
        (new PrintCertificate(caCertificate)).toString(true, true, true));
  }

  @Test
  public void testRsaKeyWithEcAlgo() throws Exception {
    assertThatThrownBy(() -> {
      generator.generate(rsaProvider.getKeyPair(),
          new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10), caNameModel);
    }).isInstanceOf(CertificateIssuanceException.class);
  }

}