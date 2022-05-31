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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;

/**
 * Default implementation of the {@link SigningCertificateRequirements} interface.
 */
public class DefaultSigningCertificateRequirements implements SigningCertificateRequirements {

  /** For serializing. */
  private static final long serialVersionUID = -1376803101192725366L;

  /** The certificate policy to use. */
  private String signingCertificateProfile;

  /** The certificate type. */
  private CertificateType certificateType;

  /** The attribute mappings, i.e., which certificate attributes to populate, and where to get the values from. */
  private List<CertificateAttributeMapping> attributeMappings;

  /**
   * Default constructor.
   */
  public DefaultSigningCertificateRequirements() {
  }

  /** {@inheritDoc} */
  @Override
  public String getSigningCertificateProfile() {
    return this.signingCertificateProfile;
  }

  /**
   * Assigns the signing certificate profile. This profile may cover things like certificate types and attribute
   * mappings (see {@link #getCertificateType()} and {@link #getAttributeMappings()}) but also more fine-grained
   * settings of how a signing certificate is created such as one or more certificate policies.
   *
   * @param signingCertificateProfile the certificate profile
   */
  public void setSigningCertificateProfile(final String signingCertificateProfile) {
    this.signingCertificateProfile = signingCertificateProfile;
  }

  /** {@inheritDoc} */
  @Override
  public CertificateType getCertificateType() {
    return this.certificateType;
  }

  /**
   * Assigns the certificate type to use.
   *
   * @param certificateType the certificate type
   */
  public void setCertificateType(final CertificateType certificateType) {
    this.certificateType = certificateType;
  }

  /** {@inheritDoc} */
  @Override
  public List<CertificateAttributeMapping> getAttributeMappings() {
    return Optional.ofNullable(this.attributeMappings).orElse(Collections.emptyList());
  }

  /**
   * Assigns the attribute mappings, i.e., a listing of which certificate attributes that should be set and where from
   * to get their values.
   *
   * @param attributeMappings mappings
   */
  public void setAttributeMappings(final List<CertificateAttributeMapping> attributeMappings) {
    this.attributeMappings = attributeMappings != null
        ? Collections.unmodifiableList(attributeMappings)
        : null;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.attributeMappings, this.certificateType, this.signingCertificateProfile);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultSigningCertificateRequirements)) {
      return false;
    }
    final DefaultSigningCertificateRequirements other = (DefaultSigningCertificateRequirements) obj;
    return Objects.equals(this.attributeMappings, other.attributeMappings)
        && this.certificateType == other.certificateType
        && Objects.equals(this.signingCertificateProfile, other.signingCertificateProfile);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("signing-certificate-policy='%s', certificate-type='%s', attribute-mappings=%s",
        this.signingCertificateProfile, this.certificateType, this.attributeMappings);
  }

}
