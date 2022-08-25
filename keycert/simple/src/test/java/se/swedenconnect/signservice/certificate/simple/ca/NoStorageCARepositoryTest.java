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
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.signservice.certificate.keyprovider.InMemoryECKeyProvider;

/**
 * No storage repository test
 */
@Slf4j
class NoStorageCARepositoryTest {

  private static File caDir;
  private static X509Certificate caCertificate;

  @BeforeAll
  private static void init() throws Exception {
    caDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    ExplicitCertNameModel caNameModel = new ExplicitCertNameModel(List.of(
      new AttributeTypeAndValueModel(CertAttributes.C, "SE"),
      new AttributeTypeAndValueModel(CertAttributes.O, "Test Org"),
      new AttributeTypeAndValueModel(CertAttributes.CN, "Test CA"),
      new AttributeTypeAndValueModel(CertAttributes.SERIALNUMBER, "1234567890")
    ));

    SelfSignedCaCertificateGenerator caf = new DefaultSelfSignedCaCertificateGenerator();

    caCertificate = caf.generate(
        (new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"))).getKeyPair(),
      new CertificateIssuerModel(
          XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, 10), caNameModel);
  }

  @Test
  void noStorageRepoTest() throws Exception {
    log.info("Testing NO Storage repository");
    NoStorageCARepository repository = new NoStorageCARepository(new File(caDir, "test.crl").getAbsolutePath());

    BigInteger certSerial = caCertificate.getSerialNumber();
    repository.addCertificate(BcFunctions.toX509CertificateHolder.apply(caCertificate));

    assertEquals(null, repository.getCertificate(certSerial));
    assertTrue(repository.getAllCertificates().isEmpty());
    assertEquals(0, repository.getCertificateCount(true));
    assertEquals(0, repository.getCertificateCount(false));
    assertNotNull(repository.getCRLRevocationDataProvider());
    assertEquals(0, repository.getCertificateRange(0, 1, false, SortBy.issueDate, true).size());
    assertEquals(BigInteger.ONE, repository.getNextCrlNumber());
    assertEquals(0, repository.removeExpiredCerts(0).size());

    X509CRLHolder crlHolder = new X509CRLHolder(Base64.decode(
        "MIIBmzCCAUECAQEwCgYIKoZIzj0EAwIwRzELMAkGA1UEBhMCU0UxETAPBgNVBAoMCFRlc3QgT3JnMRAwDgYDVQQDDAdUZXN0IENBMRMwE"
            + "QYDVQQFEwoxMjM0NTY3ODkwFw0yMjA1MjMxMzIzMThaFw0yMjA1MjMxNTM4MThaoIHIMIHFMAoGA1UdFAQDAgEBMIGNBgNVHSMEgYUwgYK"
            + "AIHnBnDC4QMV30wMSjzjxj/IQvEVGOtN1plycLKtDKnakoUukSTBHMQswCQYDVQQGEwJTRTERMA8GA1UECgwIVGVzdCBPcmcxEDAOBgNVBA"
            + "MMB1Rlc3QgQ0ExEzARBgNVBAUTCjEyMzQ1Njc4OTCCEQDvirAKZksU7Zy+QK3S3Br1MCcGA1UdHAEB/wQdMBugGaAXhhVodHRwOi8vbG9j"
            + "YWxob3N0L3Rlc3QwCgYIKoZIzj0EAwIDSAAwRQIhANOOJ1oNrxtU0jMIXym/zAtiiYW7De5HsrJYK5PTldB+AiAQ/vY9J2JN/Wv9J6TgiQ"
            + "kPJHhuPMG1zJxtTtHDwRGWaQ=="));
    repository.publishNewCrl(crlHolder);
    assertEquals(crlHolder, repository.getCurrentCrl());
  }

}