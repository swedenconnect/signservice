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
package se.swedenconnect.signservice.protocol.types;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.api.protocol.types.CertificateAttributeMapping;
import se.swedenconnect.signservice.api.protocol.types.RequestedCertificateAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;

/**
 * Default implementation of the {@link CertificateAttributeMapping} interface.
 */
public class DefaultCertificateAttributeMapping implements CertificateAttributeMapping {

  /** For serializing. */
  private static final long serialVersionUID = 896299737074279197L;

  /** A list of source attributes where the ordering is important. */
  private List<IdentityAttributeIdentifier> sources;

  /** The requested destination certificate attribute. */
  private RequestedCertificateAttribute destination;

  /** {@inheritDoc} */
  @Override
  public List<IdentityAttributeIdentifier> getSources() {
    return Optional.ofNullable(this.sources).orElse(Collections.emptyList());
  }

  /**
   * Assigns a list of signer source attributes from where the sign service gets information in order to create the
   * requested certificate attribute. If more than one attribute is given, the order is important as the sign service
   * tries the given source attributes in order.
   *
   * @param sources a list of attribute identifiers
   */
  public void setSources(final List<IdentityAttributeIdentifier> sources) {
    this.sources = sources != null
        ? Collections.unmodifiableList(sources)
        : null;
  }

  /** {@inheritDoc} */
  @Override
  public RequestedCertificateAttribute getDestination() {
    return this.destination;
  }

  /**
   * Assigns the requested destination certificate attribute.
   *
   * @param destination the certificate attribute
   */
  public void setRequestedCertificateAttribute(final RequestedCertificateAttribute destination) {
    this.destination = destination;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.destination, this.sources);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof CertificateAttributeMapping)) {
      return false;
    }
    final CertificateAttributeMapping other = (CertificateAttributeMapping) obj;
    return Objects.equals(this.destination, other.getDestination()) && Objects.equals(this.sources, other.getSources());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("destination=[%s], sources=%s", this.sources, this.destination);
  }

}
