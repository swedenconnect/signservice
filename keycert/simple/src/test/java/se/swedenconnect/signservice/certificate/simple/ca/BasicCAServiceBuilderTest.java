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

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.keyprovider.InMemoryECKeyProvider;

/**
 * CA service builder test
 */
@Slf4j
class BasicCAServiceBuilderTest {

  private static File caDir;

  @BeforeAll
  private static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    caDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
  }

  @Test
  void getInstance() throws Exception {
    final InMemoryECKeyProvider ecProvider = new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"));
    final PkiCredential caCredential = ecProvider.getKeyPair();
    final SelfSignedCaCertificateGenerator caCertificateFactory = new DefaultSelfSignedCaCertificateGenerator();
    final X509Certificate caCertificate = caCertificateFactory.generate(
        caCredential,
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
        new ExplicitCertNameModel(List.of(
            new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
            new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
            new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
            new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890"))));
    log.info("CA Certificate:\n{}", new PrintCertificate(caCertificate).toString(true, true, true));

    assertThrows(IllegalArgumentException.class, () -> BasicCAServiceBuilder.getInstance(caCredential,
        "http://localhost/testCa.crl",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        new File(caDir, "testCa.crl").toString())
        .build());
    log.info("Test acceptance of empty CA certificate list");

    caCredential.setCertificate(caCertificate);

    BasicCAServiceBuilder.getInstance(caCredential,
        "http://localhost/testCa.crl",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        new File(caDir, "testCa.crl").toString())
        .certificateStartOffset(Duration.ofSeconds(60))
        .certificateValidity(Duration.ofDays(730))
        .crlStartOffset(Duration.ofMinutes(20))
        .crlValidity(Duration.ofDays(60))
        .build();
    log.info("created instance with default CA repository");

    final BasicCAService caService = BasicCAServiceBuilder.getInstance(caCredential,
        "http://localhost/testCa.crl",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        new NoStorageCARepository(new File(caDir, "testCa.crl").getAbsolutePath()))
        .build();
    log.info("CA service created with provided CA repository");

    final PkiCredential subjectKeys = ecProvider.getKeyPair();
    final DefaultCertificateModelBuilder certificateModelBuilder = caService.getBaseCertificateModelBuilder(
        new ExplicitCertNameModel(List.of()),
        subjectKeys.getPublicKey(),
        caService.getCaCertificate(), caService.getCertificateIssuer().getCertificateIssuerModel());
    final X509CertificateHolder issuedCert = caService.issueCertificate(certificateModelBuilder.build());
    final PrintCertificate printCert = new PrintCertificate(issuedCert);
    log.info("issued certificate:\n{}", printCert.toString(true, true, true));
  }
}