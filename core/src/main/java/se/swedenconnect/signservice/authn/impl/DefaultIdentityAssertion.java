/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.authn.impl;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;

/**
 * Default implementation of the {@link IdentityAssertion} interface.
 */
public class DefaultIdentityAssertion implements IdentityAssertion {

  /** For serializing. */
  private static final long serialVersionUID = 584212468203487968L;

  /** The authentication scheme for this assertion, e.g., "SAML". */
  private String scheme;

  /** The assertion identifier. */
  private String identifier;

  /** The issuer of the assertion. */
  private String issuer;

  /** The issuence instant of the assertion. */
  private Instant issuanceInstant;

  /** The instant the user was authenticated. */
  private Instant authnInstant;

  /** The authentication context ID under which the authentication was made. */
  private AuthnContextIdentifier authnContextIdentifier;

  /** The identity attributes. */
  private List<IdentityAttribute<?>> identityAttributes;

  /** The encoded assertion. */
  private byte[] encodedAssertion;



  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getScheme() {
    return this.scheme;
  }

  /**
   * Assigns the authentication scheme for this assertion, e.g., "SAML".
   * @param scheme the authentication scheme
   */
  public void setScheme(@Nonnull final String scheme) {
    this.scheme = scheme;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getIdentifier() {
    return this.identifier;
  }

  /**
   * Assigns the assertion identifier.
   *
   * @param identifier the assertion identifier
   */
  @Nonnull
  public void setIdentifier(@Nonnull final String identifier) {
    this.identifier = identifier;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getIssuer() {
    return this.issuer;
  }

  /**
   * Assigns the issuer of the assertion.
   *
   * @param issuer the issuer ID
   */
  public void setIssuer(@Nonnull final String issuer) {
    this.issuer = issuer;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Instant getIssuanceInstant() {
    return this.issuanceInstant;
  }

  /**
   * Assigns the issuance instant of the assertion.
   *
   * @param issuanceInstant the issuance instant
   */
  public void setIssuanceInstant(@Nonnull final Instant issuanceInstant) {
    this.issuanceInstant = issuanceInstant;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Instant getAuthnInstant() {
    return this.authnInstant;
  }

  /**
   * Assigns the instant the user authentication took place.
   *
   * @param authnInstant the authentication instant
   */
  public void setAuthnInstant(@Nonnull final Instant authnInstant) {
    this.authnInstant = authnInstant;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuthnContextIdentifier getAuthnContext() {
    return this.authnContextIdentifier;
  }

  /**
   * Assigns the authentication context ID under which the authentication was made.
   *
   * @param authnContextIdentifier the authentication context ID
   */
  public void setAuthnContext(@Nonnull final AuthnContextIdentifier authnContextIdentifier) {
    this.authnContextIdentifier = authnContextIdentifier;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<IdentityAttribute<?>> getIdentityAttributes() {
    return this.identityAttributes != null ? this.identityAttributes : Collections.emptyList();
  }

  /**
   * Assigns the identity attributes from the authentication.
   *
   * @param identityAttributes the identity attributes
   */
  public void setIdentityAttributes(@Nonnull final List<IdentityAttribute<?>> identityAttributes) {
    this.identityAttributes = identityAttributes != null
        ? Collections.unmodifiableList(identityAttributes)
        : null;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public byte[] getEncodedAssertion() {
    return this.encodedAssertion != null ? this.encodedAssertion.clone() : null;
  }

  /**
   * Assigns the encoded assertion.
   *
   * @param encodedAssertion the encoded assertion
   */
  public void setEncodedAssertion(@Nonnull final byte[] encodedAssertion) {
    this.encodedAssertion = encodedAssertion;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(this.encodedAssertion);
    result = prime * result + Objects.hash(this.scheme, this.authnContextIdentifier, this.authnInstant,
        this.identityAttributes, this.issuanceInstant, this.issuer, this.identifier);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultIdentityAssertion)) {
      return false;
    }
    final IdentityAssertion other = (IdentityAssertion) obj;
    return Objects.equals(this.authnContextIdentifier, other.getAuthnContext())
        && Objects.equals(this.authnInstant, other.getAuthnInstant())
        && Arrays.equals(this.encodedAssertion, other.getEncodedAssertion())
        && Objects.equals(this.identityAttributes, other.getIdentityAttributes())
        && Objects.equals(this.issuanceInstant, other.getIssuanceInstant())
        && Objects.equals(this.issuer, other.getIssuer())
        && Objects.equals(this.identifier, other.getIdentifier())
        && Objects.equals(this.scheme, other.getScheme());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "scheme='%s', id='%s', issuer='%s', issuance-instant='%s', authn-instant='%s', "
            + "authn-context-identifier=%s, identity-attributes=%s, encoded-assertion=[%d bytes]",
        this.scheme, this.identifier, this.issuer, this.issuanceInstant, this.authnInstant, this.authnContextIdentifier,
        this.getIdentityAttributes(), this.encodedAssertion != null ? this.encodedAssertion.length : 0);
  }

}
