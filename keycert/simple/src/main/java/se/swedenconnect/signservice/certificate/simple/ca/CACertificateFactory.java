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

import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;

import java.security.KeyPair;
import java.security.cert.CertificateException;

/**
 * Factory for creating self issued CA certificates
 */
public interface CACertificateFactory {

  /**
   * Create CA certificate
   *
   * @param certificateIssuerModel parameters determining type and validity of issued certificate
   * @param name the subject and issuer name of the CA
   * @param caKeyPair the public and private ca issuing key
   * @return CA certificate
   * @throws CertificateException error creating the certificate
   */
  X509CertificateHolder getCACertificate(final CertificateIssuerModel certificateIssuerModel,
    final CertNameModel<?> name,
    final KeyPair caKeyPair) throws CertificateException;
}
