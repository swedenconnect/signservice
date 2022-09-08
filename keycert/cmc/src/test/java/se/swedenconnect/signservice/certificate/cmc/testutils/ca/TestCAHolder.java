/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.revocation.ocsp.impl.RepositoryBasedOCSPResponder;
import se.swedenconnect.security.credential.BasicCredential;

/**
 * This class when instantiated creates a test CA services.
 */
@Slf4j
public class TestCAHolder {

  public static final String FILE_URL_PREFIX = "http://file.example.com/";

  private final File dataDir;
  @Getter
  private TestCAService cscaService;
  @Getter
  public final TestCA caConfig;

  /**
   * Constructor for creating an instance of a test CSCA service
   *
   * @param caConfig Configuration parameters from the CSCA service
   */
  public TestCAHolder(final TestCA caConfig) {
    this.dataDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
    this.caConfig = caConfig;
    try {
      this.setupCAs();
    }
    catch (final Exception e) {
      e.printStackTrace();
    }
  }

  private void setupCAs() throws Exception {
    log.info("Setting up test CA {}", this.caConfig.getId());
    this.cscaService = this.createCSCAService();
    this.addOCSPResponder();
  }

  private TestCAService createCSCAService() throws Exception {
    // generate key and root CA cert
    final CertificateIssuer certificateIssuer = new SelfIssuedCertificateIssuer(new CertificateIssuerModel(
        this.caConfig.getCaAlgo(), Duration.ofDays(365)));

    log.info("Generating root ca key for {}", this.caConfig.getId());
    final KeyPair kp = this.caConfig.getCaKeyPair();
    final CertNameModel<?> name = this.getCAName(this.caConfig.getCaName());

    final CertificateModelBuilder builder =
        SelfIssuedCertificateModelBuilder.getInstance(kp, certificateIssuer.getCertificateIssuerModel())
            .subject(name)
            .basicConstraints(new BasicConstraintsModel(true, true))
            .includeSki(true)
            .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
            .certificatePolicy(new CertificatePolicyModel(true));
    final X509CertificateHolder rootCA01Cert = certificateIssuer.issueCertificate(builder.build());
    final File crlFile = new File(this.dataDir, this.caConfig.getId() + "/root-ca.crl");

    return new TestCAService(
        new BasicCredential(CertificateUtils.decodeCertificate(rootCA01Cert.getEncoded()), kp.getPrivate()),
        new TestCARepository(crlFile), crlFile, this.caConfig.getCaAlgo());
  }

  private CertNameModel<?> getCAName(final String commonName) {
    return new ExplicitCertNameModel(Arrays.asList(
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.C)
            .value(this.caConfig.getCountry()).build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.O)
            .value("Test Org").build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.CN)
            .value(commonName).build()));
  }

  private void addOCSPResponder() {
    try {
      log.info("Generating ocsp responder key for {}", this.caConfig.getId());

      KeyPair kp;
      String algorithm;
      List<X509CertificateHolder> ocspServiceChain;
      if (this.caConfig.getOcspKeyPair() != null) {
        // There is a dedicated key for OCSP responses. Setup an authorized responder
        kp = this.caConfig.getOcspKeyPair();
        algorithm = this.caConfig.getOcspAlgo();
        final DefaultCertificateModelBuilder certModelBuilder = this.cscaService.getCertificateModelBuilder(
            getTypicalServiceName(this.caConfig.getOcspName(), this.caConfig.getCountry()), kp.getPublic());

        certModelBuilder
            .qcStatements(null)
            .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
            .crlDistributionPoints(null)
            .ocspServiceUrl(null)
            .ocspNocheck(true)
            .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_OCSPSigning));

        final X509CertificateHolder ocspIssuerCert =
            this.cscaService.getCertificateIssuer().issueCertificate(certModelBuilder.build());
        ocspServiceChain = Arrays.asList(
            ocspIssuerCert,
            this.cscaService.getCaCertificate());

      }
      else {
        // We are issuing OCSP response directly from CA
        kp = this.caConfig.getCaKeyPair();
        algorithm = this.caConfig.getCaAlgo();
        ocspServiceChain = Arrays.asList(
            this.cscaService.getCaCertificate());
      }

      final OCSPModel ocspModel = new OCSPModel(this.cscaService.getCaCertificate(), algorithm);
      final OCSPResponder ocspResponder =
          new RepositoryBasedOCSPResponder(new BasicCredential(kp.getPublic(), kp.getPrivate()), ocspModel,
              this.cscaService.getCaRepository());
      this.cscaService.setOcspResponder(ocspResponder, "https://example.com/" + this.caConfig.getId() + "/ocsp",
          ocspServiceChain.get(0));
    }
    catch (final Exception ex) {
      log.error("Error creating OCSP responder", ex);
    }
  }

  public static String getFileUrl(final File file) {
    return getFileUrl(file.getAbsolutePath());
  }

  public static String getFileUrl(final String path) {
    final String urlEncodedPath = URLEncoder.encode(path, StandardCharsets.UTF_8);
    return FILE_URL_PREFIX + urlEncodedPath;
  }

  public static CertNameModel<?> getTypicalServiceName(final String commonName, final String country) {
    final CertNameModel<?> subjectName = new ExplicitCertNameModel(Arrays.asList(
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.C)
            .value(country).build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.O)
            .value("Organization AB").build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.OU)
            .value("Service department").build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.ORGANIZATION_IDENTIFIER)
            .value("556677-1122").build(),
        AttributeTypeAndValueModel.builder()
            .attributeType(CertAttributes.CN)
            .value(commonName).build()));
    return subjectName;
  }

}
