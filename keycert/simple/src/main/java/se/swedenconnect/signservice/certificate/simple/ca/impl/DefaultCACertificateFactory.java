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
package se.swedenconnect.signservice.certificate.simple.ca.impl;

import lombok.NonNull;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.simple.ca.CACertificateFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;

/**
 * Default CA certificate factory.
 */
public class DefaultCACertificateFactory implements CACertificateFactory {

  /**
   * Constructor for the CA certificate factory
   */
  public DefaultCACertificateFactory() {
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder getCACertificate(@NonNull final CertificateIssuerModel certificateIssuerModel,
      @NonNull final CertNameModel<?> name, @NonNull final PkiCredential caKeyPair) throws CertificateException {
    try {
      final BasicCertificateIssuer issuer = new BasicCertificateIssuer(certificateIssuerModel,
          CAUtils.getX500Name(name, new AttributeValueEncoder()),
          caKeyPair.getPrivateKey());
      final CertificateModel certificateModel = SelfIssuedCertificateModelBuilder.getInstance(new KeyPair(
            caKeyPair.getPublicKey(), caKeyPair.getPrivateKey()),
          certificateIssuerModel)
          .subject(name)
          .basicConstraints(new BasicConstraintsModel(true, true))
          .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
          .includeSki(true)
          .certificatePolicy(new CertificatePolicyModel(true))
          .build();
      return issuer.issueCertificate(certificateModel);
    }
    catch (final IOException e) {
      throw new CertificateException("Error creating ca certificate", e);
    }
  }
}
