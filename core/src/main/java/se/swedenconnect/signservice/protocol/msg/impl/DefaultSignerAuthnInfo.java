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

import java.util.Objects;

import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.protocol.msg.SignerAuthnInfo;

/**
 * Default implementation of the {@link SignerAuthnInfo} interface.
 */
public class DefaultSignerAuthnInfo implements SignerAuthnInfo {

  /** For serializing. */
  private static final long serialVersionUID = 5480035129919906816L;

  /** The authentication scheme. */
  private final String scheme;

  /** The identity assertion. */
  private final IdentityAssertion identityAssertion;

  /**
   * Constructor.
   *
   * @param scheme the authentication scheme
   * @param identityAssertion the identity assertion
   */
  public DefaultSignerAuthnInfo(final String scheme, final IdentityAssertion identityAssertion) {
    this.scheme = Objects.requireNonNull(scheme, "scheme must not be null");
    this.identityAssertion = Objects.requireNonNull(identityAssertion, "identityAssertion must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getScheme() {
    return this.scheme;
  }

  /** {@inheritDoc} */
  @Override
  public IdentityAssertion getIdentityAssertion() {
    return this.identityAssertion;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.identityAssertion, this.scheme);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof SignerAuthnInfo)) {
      return false;
    }
    final SignerAuthnInfo other = (SignerAuthnInfo) obj;
    return Objects.equals(this.identityAssertion, other.getIdentityAssertion())
        && Objects.equals(this.scheme, other.getScheme());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("scheme='%s', identity-assertion=[%s]", this.scheme, this.identityAssertion);
  }

}
