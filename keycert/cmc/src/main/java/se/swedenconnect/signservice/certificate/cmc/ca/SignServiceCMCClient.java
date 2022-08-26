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

package se.swedenconnect.signservice.certificate.cmc.ca;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;

import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.client.impl.PreConfiguredCMCClient;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.KeyUsageCalculator;

/**
 * CMC Client for certificate services
 */
public class SignServiceCMCClient extends PreConfiguredCMCClient {

  /**
   * Optional certificate profile to be adopted in issued certificates.
   */
  private CertificateProfileConfiguration profileConfiguration;

  /**
   * Constructor for the CMC Client
   *
   * @param cmcRequestUrl URL where CMC requests are sent to the remote CA
   * @param cmcCredential the CMC credential (private key and certificate)
   * @param algorithm CMC signing algorithm
   * @param cmcResponseCert signing certificate of the remote CA CMC responder
   * @param staticCaInformation static information about the issuing CA
   * @throws MalformedURLException malformed URL
   * @throws NoSuchAlgorithmException algorithm is not supported or recognized
   * @throws OperatorCreationException error setting up CMC client
   * @throws CertificateEncodingException error parsing provided certificates
   */
  public SignServiceCMCClient(@Nonnull final String cmcRequestUrl,
      @Nonnull final PkiCredential cmcCredential, @Nonnull final String algorithm,
      @Nonnull final X509Certificate cmcResponseCert, @Nonnull final CMCCaInformation staticCaInformation)
      throws MalformedURLException, NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException {
    super(cmcRequestUrl, cmcCredential.getPrivateKey(), cmcCredential.getCertificate(), algorithm, cmcResponseCert,
        Optional.ofNullable(staticCaInformation).map(CMCCaInformation::toStaticCAInformation).orElse(null));
  }

  /**
   * Return a certificate model builder prepared for creating certificate models for certificate requests to this CA
   * service via CMC.
   *
   * @param subjectPublicKey the public key of the subject
   * @param subject subject name data
   * @param includeCrlDPs true to include CRL distribution point URLs in the issued certificate
   * @param includeOcspURL true to include OCSP URL (if present) in the issued certificate
   * @return certificate model builder
   * @throws IOException errors obtaining the certificate model builder
   */
  @Override
  @Nonnull
  public CMCCertificateModelBuilder getCertificateModelBuilder(@Nonnull final PublicKey subjectPublicKey,
      @Nonnull final CertNameModel<?> subject, final boolean includeCrlDPs, final boolean includeOcspURL)
      throws IOException {

    try {
      final StaticCAInformation caInformation = this.getStaticCAInformation();
      final X509CertificateHolder caIssuerCert = new JcaX509CertificateHolder(this.caCertificate);
      final CMCCertificateModelBuilder certModelBuilder = CMCCertificateModelBuilder.getInstance(
          subjectPublicKey, caIssuerCert, caInformation.getCaAlgorithm());

      certModelBuilder.subject(subject);

      // Apply certificate profile
      //
      final CertificateProfileConfiguration conf =
          Optional.ofNullable(this.profileConfiguration).orElseGet(() -> new CertificateProfileConfiguration());

      if (CollectionUtils.isNotEmpty(conf.getExtendedKeyUsages())) {
        certModelBuilder.extendedKeyUsage(new ExtendedKeyUsageModel(conf.isExtendedKeyUsageCritical(),
            conf.getExtendedKeyUsages().stream().map(s -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(s)))
                .toArray(KeyPurposeId[]::new)));
      }
      if (CollectionUtils.isNotEmpty(conf.getPolicies())) {
        certModelBuilder.certificatePolicy(new CertificatePolicyModel(conf.isPoliciesCritical(),
            conf.getPolicies().stream().map(ASN1ObjectIdentifier::new).toArray(ASN1ObjectIdentifier[]::new)));
      }
      certModelBuilder
          .basicConstraints(new BasicConstraintsModel(false, conf.isBasicConstraintsCritical()))
          .keyUsage(new KeyUsageModel(KeyUsageCalculator.getKeyUsageValue(subjectPublicKey, conf.getUsageDirective())));

      if (includeCrlDPs) {
        certModelBuilder.crlDistributionPoints(caInformation.getCrlDpURLs());
      }
      if (includeOcspURL) {
        certModelBuilder.ocspServiceUrl(caInformation.getOcspResponserUrl());
      }

      return certModelBuilder;
    }
    catch (final CertificateEncodingException e) {
      throw new IOException(e);
    }
  }

  /**
   * Optional certificate profile to be adopted in issued certificates.
   *
   * @param profileConfiguration certificate profile configuration
   */
  public void setProfileConfiguration(@Nullable final CertificateProfileConfiguration profileConfiguration) {
    this.profileConfiguration = profileConfiguration;
  }

}
