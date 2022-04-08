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
package se.swedenconnect.signservice.client.impl;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;

/**
 * Default implementation of the {@link ClientConfiguration} interface.
 */
public class DefaultClientConfiguration implements ClientConfiguration {

  /** The client ID. */
  private final String clientId;

  /** The client certificate(s). */
  private List<X509Certificate> trustedCertificates;

  /** The registered client response URL:s. */
  private List<String> responseUrls;

  /**
   * Constructor.
   *
   * @param clientId the client ID
   */
  public DefaultClientConfiguration(final String clientId) {
    this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getClientId() {
    return this.clientId;
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getTrustedCertificates() {
    return this.trustedCertificates != null ? Collections.unmodifiableList(this.trustedCertificates) : null;
  }

  /**
   * Assigns a list of the client certificate(s).
   *
   * @param trustedCertificates client certificates
   */
  public void setTrustedCertificates(final List<X509Certificate> trustedCertificates) {
    this.trustedCertificates = trustedCertificates;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getResponseUrls() {
    return this.responseUrls != null ? Collections.unmodifiableList(this.responseUrls) : null;
  }

  /**
   * Assigns the registered client response URL:s.
   *
   * @param responseUrls response URL:s
   */
  public void setResponseUrls(final List<String> responseUrls) {
    this.responseUrls = responseUrls;
  }

  /** {@inheritDoc} */
  @GeneratedMethod
  @Override
  public int hashCode() {
    return Objects.hash(this.clientId, this.responseUrls, this.trustedCertificates);
  }

  /** {@inheritDoc} */
  @GeneratedMethod
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultClientConfiguration)) {
      return false;
    }
    final DefaultClientConfiguration other = (DefaultClientConfiguration) obj;
    return Objects.equals(this.clientId, other.clientId) && Objects.equals(this.responseUrls, other.responseUrls)
        && Objects.equals(this.trustedCertificates, other.trustedCertificates);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {

    final Function<X509Certificate, String> toStringFunc = (c) -> {
      StringBuffer sb = new StringBuffer("[");
      sb.append(CertificateUtils.toLogString(c));
      sb.append("]");
      return sb.toString();
    };

    return String.format("client-id='%s', trusted-certificates=%s, response-urls=%s",
        this.clientId,
        Optional.ofNullable(this.trustedCertificates)
            .map(t -> t.stream().map(toStringFunc).collect(Collectors.toList()))
            .orElse(Collections.emptyList()),
        Optional.ofNullable(this.responseUrls).orElse(Collections.emptyList()));
  }

}
