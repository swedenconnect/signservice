/*
 * Copyright 2022-2024 Sweden Connect
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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignatureActivationRequestData;

/**
 * Default implementation of {@link AuthnRequirements}.
 */
public class DefaultAuthnRequirements implements AuthnRequirements {

  /** For serializing. */
  private static final long serialVersionUID = 6171331661608238161L;

  /** The ID for the authentication service. */
  private String authnServiceID;

  /** The authentication profile. */
  private String authnProfile;

  /** Authentication context identifiers. */
  private List<AuthnContextIdentifier> authnContextIdentifiers;

  /** The requested signer attributes. */
  private List<IdentityAttribute<?>> requestedSignerAttributes;

  /** The SAD request data. */
  private SignatureActivationRequestData signatureActivationRequestData;

  /**
   * Default constructor.
   */
  public DefaultAuthnRequirements() {
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getAuthnServiceID() {
    return this.authnServiceID;
  }

  /**
   * Assigns the ID for the authentication service.
   *
   * @param authnServiceID the authentication service ID
   */
  public void setAuthnServiceID(@Nonnull final String authnServiceID) {
    this.authnServiceID = authnServiceID;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getAuthnProfile() {
    return this.authnProfile;
  }

  /**
   * Assigns the authentication profile.
   *
   * @param authnProfile the authentication profile
   */
  public void setAuthnProfile(@Nonnull final String authnProfile) {
    this.authnProfile = authnProfile;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<AuthnContextIdentifier> getAuthnContextIdentifiers() {
    return Optional.ofNullable(this.authnContextIdentifiers).orElseGet(() -> Collections.emptyList());
  }

  /**
   * Assigns the authentication context identifiers.
   *
   * @param authnContextIdentifiers the authentication context identifiers
   */
  public void setAuthnContextIdentifiers(@Nonnull final List<AuthnContextIdentifier> authnContextIdentifiers) {
    this.authnContextIdentifiers = authnContextIdentifiers != null
        ? Collections.unmodifiableList(authnContextIdentifiers)
        : null;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<IdentityAttribute<?>> getRequestedSignerAttributes() {
    return Optional.ofNullable(this.requestedSignerAttributes).orElseGet(() -> Collections.emptyList());
  }

  /**
   * Assigns the requested signer attributes.
   *
   * @param requestedSignerAttributes the requested signer attributes
   */
  public void setRequestedSignerAttributes(@Nonnull final List<IdentityAttribute<?>> requestedSignerAttributes) {
    this.requestedSignerAttributes = requestedSignerAttributes != null
        ? Collections.unmodifiableList(requestedSignerAttributes)
        : null;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public SignatureActivationRequestData getSignatureActivationRequestData() {
    return this.signatureActivationRequestData;
  }

  /**
   * Assigns SAD request data. See {@link SignatureActivationRequestData}.
   *
   * @param sadRequestData the SAD request data
   */
  public void setSignatureActivationRequestData(@Nonnull final SignatureActivationRequestData sadRequestData) {
    this.signatureActivationRequestData = sadRequestData;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.authnContextIdentifiers, this.authnProfile, this.authnServiceID,
        this.requestedSignerAttributes, this.signatureActivationRequestData);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultAuthnRequirements)) {
      return false;
    }
    final DefaultAuthnRequirements other = (DefaultAuthnRequirements) obj;
    return Objects.equals(this.authnContextIdentifiers, other.authnContextIdentifiers)
        && Objects.equals(this.authnProfile, other.authnProfile)
        && Objects.equals(this.authnServiceID, other.authnServiceID)
        && Objects.equals(this.requestedSignerAttributes, other.requestedSignerAttributes)
        && Objects.equals(this.signatureActivationRequestData, other.signatureActivationRequestData);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("authn-service-id='%s', authn-profile='%s', "
        + "authn-context-identifiers=%s, requested-signer-attributes=%s, sad-request-data=[%s]",
        this.authnServiceID, this.authnProfile, this.authnContextIdentifiers, this.requestedSignerAttributes,
        this.signatureActivationRequestData);
  }

}
