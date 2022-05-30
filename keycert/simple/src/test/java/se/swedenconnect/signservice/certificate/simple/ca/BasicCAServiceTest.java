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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.DefaultSignServiceSigningKeyProvider;
import se.swedenconnect.signservice.certificate.simple.ca.impl.DefaultCACertificateFactory;

/**
 * Basic CA service test
 */
@Slf4j
class BasicCAServiceTest {

  private static File caDir;

  @BeforeAll
  private static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    caDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
  }

  @Test
  void caServiceTest() throws Exception {
    SignServiceSigningKeyProvider keyProvider = new DefaultSignServiceSigningKeyProvider(2048, 5,
      new ECGenParameterSpec("P-256"));
    PkiCredential keyPair = keyProvider.getSigningKeyPair("EC");
    CACertificateFactory caCertificateFactory = new DefaultCACertificateFactory();
    X509CertificateHolder caCertificate = caCertificateFactory.getCACertificate(
      new CertificateIssuerModel(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10),
      new ExplicitCertNameModel(List.of(
        new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
        new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
        new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
        new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890")
      )), keyPair
    );
    log.info("CA Certificate:\n{}", (new PrintCertificate(caCertificate)).toString(true, true, true));

    BasicCAService caService = CAServiceBuilder.getInstance(
      keyPair.getPrivateKey(), List.of(caCertificate), "http://localhost/test",
      XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, new File(caDir, "ca.crl")
    ).build();

    caService.setOcspResponder(Mockito.mock(OCSPResponder.class), "http:localhost/ocsp", caCertificate);
    assertEquals(caCertificate, caService.getCaCertificate());
    assertEquals(caCertificate, caService.getOCSPResponderCertificate());
    assertEquals("http:localhost/ocsp", caService.getOCSPResponderURL());
    assertEquals("http://localhost/test", caService.getCrlDpURLs().get(0));
    assertNotNull(caService.getOCSPResponder());
    assertEquals(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, caService.getCaAlgorithm());
    assertTrue(caService.getCertificateIssuer() instanceof CertificateIssuer);

  }
}