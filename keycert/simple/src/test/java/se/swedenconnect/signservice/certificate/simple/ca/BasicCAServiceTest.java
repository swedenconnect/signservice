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
package se.swedenconnect.signservice.certificate.simple.ca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

/**
 * Basic CA service test
 */
@Slf4j
class BasicCAServiceTest {

  private static File caDir;

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
  void caServiceTest() throws Exception {
    final PkiCredentialContainer ecProvider = new SoftPkiCredentialContainer("BC", "Test1234");

    final PkiCredential caCredential = ecProvider.getCredential(ecProvider.generateCredential(KeyGenType.EC_P256));
    final SelfSignedCaCertificateGenerator caCertificateFactory = new DefaultSelfSignedCaCertificateGenerator();
    final X509Certificate caCertificate = caCertificateFactory.generate(
        caCredential,
        new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, Duration.ofDays(365)),
        new ExplicitCertNameModel(List.of(
            new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
            new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
            new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
            new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890"))));
    caCredential.setCertificate(caCertificate);
    log.info("CA Certificate:\n{}", new PrintCertificate(caCertificate).toString(true, true, true));

    final BasicCAService caService = BasicCAServiceBuilder.getInstance(caCredential, "http://localhost/test",
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, new File(caDir, "ca.crl").getAbsolutePath()).build();

    caService.setOcspResponder(Mockito.mock(OCSPResponder.class), "http:localhost/ocsp", caCertificate);
    assertEquals(caCertificate, BcFunctions.toX509Certificate.apply(caService.getCaCertificate()));
    assertEquals(caCertificate, BcFunctions.toX509Certificate.apply(caService.getOCSPResponderCertificate()));
    assertEquals("http:localhost/ocsp", caService.getOCSPResponderURL());
    assertEquals("http://localhost/test", caService.getCrlDpURLs().get(0));
    assertNotNull(caService.getOCSPResponder());
    assertEquals(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, caService.getCaAlgorithm());
    assertTrue(caService.getCertificateIssuer() instanceof CertificateIssuer);

  }
}