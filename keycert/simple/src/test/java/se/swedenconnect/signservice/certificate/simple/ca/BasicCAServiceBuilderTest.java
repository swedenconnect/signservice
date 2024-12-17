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

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
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
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.SigningKeyUsageDirective;

/**
 * CA service builder test
 */
@Slf4j
class BasicCAServiceBuilderTest {

  private static File caDir;
  private static String TEST_CRL = "testCa.crl";

  @BeforeAll
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    caDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
  }

  @AfterAll
  public static void clean() throws Exception {
    FileUtils.deleteDirectory(caDir);
  }

  @Test
  void getInstance() throws Exception {
    final PkiCredentialContainer caKeyProvider = new SoftPkiCredentialContainer("BC","Test1234");
    final PkiCredential caCredential = caKeyProvider.getCredential(caKeyProvider.generateCredential(KeyGenType.EC_P256));
    final SelfSignedCaCertificateGenerator caCertificateFactory = new DefaultSelfSignedCaCertificateGenerator();
    final X509Certificate caCertificate = caCertificateFactory.generate(
        caCredential,
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, Duration.ofDays(365)),
        new ExplicitCertNameModel(List.of(
            new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
            new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
            new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
            new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890"))));
    log.info("CA Certificate:\n{}", new PrintCertificate(caCertificate).toString(true, true, true));
    caCredential.setCertificate(caCertificate);

    BasicCAServiceBuilder.getInstance(caCredential,
        "http://localhost/testCa.crl",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        new File(caDir, TEST_CRL).toString())
        .certificateStartOffset(Duration.ofSeconds(60))
        .certificateValidity(Duration.ofDays(730))
        .crlStartOffset(Duration.ofMinutes(20))
        .crlValidity(Duration.ofDays(60))
        .build();
    log.info("created instance with default CA repository");

    final BasicCAService caService = BasicCAServiceBuilder.getInstance(caCredential,
        "http://localhost/testCa.crl",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        new NoStorageCARepository(new File(caDir, TEST_CRL).getAbsolutePath()))
        .build();
    log.info("CA service created with provided CA repository");
    CertificateProfileConfiguration certProfileConfig = CertificateProfileConfiguration.builder()
      .policies(List.of("1.2.3.4.5.6.7"))
      .extendedKeyUsageCritical(true)
      .extendedKeyUsages(List.of("2.3.4.5.6.7.8", "2.4.5.6.7.8.9"))
      .usageDirective(SigningKeyUsageDirective.builder().excludeNonRepudiation(true).encrypt(true).build())
      .build();
    caService.setProfileConfiguration(certProfileConfig);

    final PkiCredential subjectKeys = caKeyProvider.getCredential(caKeyProvider.generateCredential(KeyGenType.EC_P256));
    final DefaultCertificateModelBuilder certificateModelBuilder = caService.getBaseCertificateModelBuilder(
        new ExplicitCertNameModel(List.of()),
        subjectKeys.getPublicKey(),
        caService.getCaCertificate(), caService.getCertificateIssuer().getCertificateIssuerModel());
    final X509CertificateHolder issuedCert = caService.issueCertificate(certificateModelBuilder.build());
    final PrintCertificate printCert = new PrintCertificate(issuedCert);
    log.info("issued certificate:\n{}", printCert.toString(true, true, true));
  }
}
