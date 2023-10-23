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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * An interface for a generator that generates self-signed (self-issued) CA certificates.
 */
public interface SelfSignedCaCertificateGenerator {

  /**
   * Generates the self-issued CA certificates.
   *
   * @param KeyPairCredentials the public and private ca issuing key
   * @param certificateIssuerModel parameters determining type and validity of issued certificate
   * @param name the subject and issuer name of the CA
   * @return CA certificate
   * @throws CertificateException error creating the certificate
   */
  @Nonnull
  X509Certificate generate(
      @Nonnull final PkiCredential KeyPairCredentials, @Nonnull final CertificateIssuerModel certificateIssuerModel,
      @Nonnull final CertNameModel<?> name) throws CertificateException;
}
