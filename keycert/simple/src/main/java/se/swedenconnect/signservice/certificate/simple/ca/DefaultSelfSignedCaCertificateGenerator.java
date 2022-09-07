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

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * Default implementation of the {@link SelfSignedCaCertificateGenerator} interface.
 */
public class DefaultSelfSignedCaCertificateGenerator implements SelfSignedCaCertificateGenerator {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public X509Certificate generate(
      @Nonnull final PkiCredential keyPair, @Nonnull final CertificateIssuerModel certificateIssuerModel,
      @Nonnull final CertNameModel<?> name) throws CertificateException {

    try {
      final CertificateIssuer issuer = new SelfIssuedCertificateIssuer(certificateIssuerModel);
      final CertificateModel certificateModel = SelfIssuedCertificateModelBuilder.getInstance(
          new KeyPair(keyPair.getPublicKey(), keyPair.getPrivateKey()), certificateIssuerModel)
          .subject(name)
          .basicConstraints(new BasicConstraintsModel(true, true))
          .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
          .includeSki(true)
          .certificatePolicy(new CertificatePolicyModel(true))
          .build();

      X509CertificateHolder certificate = issuer.issueCertificate(certificateModel);
      return X509Utils.decodeCertificate(certificate.getEncoded());
    }
    catch (final IOException e) {
      throw new CertificateException("Error creating CA certificate", e);
    }
  }

}
