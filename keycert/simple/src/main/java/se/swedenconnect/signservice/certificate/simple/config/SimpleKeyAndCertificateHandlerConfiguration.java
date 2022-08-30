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
package se.swedenconnect.signservice.certificate.simple.config;

import java.time.Duration;
import java.util.Objects;

import javax.annotation.Nonnull;

import org.apache.xml.security.signature.XMLSignature;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.certificate.simple.SimpleKeyAndCertificateHandler;

/**
 * Configuration for {@link SimpleKeyAndCertificateHandler}.
 */
public class SimpleKeyAndCertificateHandlerConfiguration extends AbstractKeyAndCertificateHandlerConfiguration {

  /**
   * The application base URL. Must not end with a slash.
   */
  @Getter
  private String baseUrl;

  /**
   * The CA credential (private key and certificate(s)).
   */
  @Getter
  @Setter
  private PkiCredential caCredential;

  /**
   * The CA signing algorithm. Defaults to {@value XMLSignature#ALGO_ID_SIGNATURE_RSA_SHA256} or
   * {@value XMLSignature#ALGO_ID_SIGNATURE_ECDSA_SHA256} depending on the type of client credentials used.
   */
  @Getter
  @Setter
  private String caSigningAlgorithm;

  /**
   * The validity for issued certificates. The default is 1 year.
   */
  @Getter
  @Setter
  private Duration certValidity;

  /**
   * The validity for issued CRL:s. The default is 2 days.
   */
  @Getter
  @Setter
  private Duration crlValidity;

  /**
   * The path to where CRL:s are exposed. Relative to {@code baseUrl}.
   */
  @Getter
  private String crlDpPath;

  /**
   * Even though revocation is not supported we need to support an empty CRL. This property tells where to store this
   * CRL locally.
   */
  @Getter
  @Setter
  private String crlFileLocation;

  /**
   * Assigns the application base URL. Must not end with a slash.
   *
   * @param baseUrl the application base URL
   */
  public void setBaseUrl(@Nonnull final String baseUrl) {
    this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
    if (this.baseUrl.endsWith("/")) {
      throw new IllegalArgumentException("The baseUrl must not end with a '/'");
    }
  }

  /**
   * Assigns the path to where CRL:s are exposed. Relative to {@code baseUrl}.
   *
   * @param crlDpPath the CRL distribution path
   */
  public void setCrlDpPath(@Nonnull final String crlDpPath) {
    this.crlDpPath = Objects.requireNonNull(crlDpPath, "crlDpPath must not be null");
    if (!this.crlDpPath.startsWith("/")) {
      throw new IllegalArgumentException("The crlDpPath must begin with a '/'");
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return SimpleKeyAndCertificateHandlerFactory.class.getName();
  }

}
