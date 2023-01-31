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
package se.swedenconnect.signservice.certificate.cmc.config;

import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import org.apache.xml.security.signature.XMLSignature;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.ca.cmc.api.client.impl.HttpProxyConfiguration;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.certificate.cmc.CMCKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.cmc.CertificateRequestFormat;
import se.swedenconnect.signservice.certificate.cmc.RemoteCaInformation;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;

/**
 * Configuration class for {@link CMCKeyAndCertificateHandler}.
 */
public class CMCKeyAndCertificateHandlerConfiguration extends AbstractKeyAndCertificateHandlerConfiguration {

  /**
   * The URL for sending CMC requests.
   */
  @Getter
  @Setter
  private String cmcRequestUrl;

  /**
   * The CMC client credential.
   */
  @Setter
  @Getter
  private PkiCredentialConfiguration cmcClientCredential;

  /**
   * The CMC signing algorithm. Defaults to {@value XMLSignature#ALGO_ID_SIGNATURE_RSA_SHA256} or
   * {@value XMLSignature#ALGO_ID_SIGNATURE_ECDSA_SHA256} depending on the type of client credentials used.
   */
  @Getter
  @Setter
  private String cmcSigningAlgorithm;

  /**
   * The CMC responder certificate.
   */
  @Getter
  @Setter
  private X509Certificate cmcResponderCertificate;

  /**
   * The CA information needed by the CMC client.
   */
  @Getter
  @Setter
  private RemoteCaInformation remoteCaInfo;

  /**
   * HTTP proxy configuration
   */
  @Setter
  @Getter
  private HttpProxyConfiguration cmcClientProxy;

  /**
   * Certificate request format (crmf or pkcs10)
   */
  @Setter
  @Getter
  private CertificateRequestFormat certificateRequestFormat;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return CMCKeyAndCertificateHandlerFactory.class.getName();
  }

}
