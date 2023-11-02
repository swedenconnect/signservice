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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.util.Objects;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.protocol.msg.SignatureActivationRequestData;

/**
 * Default implementation of the {@link SignatureActivationRequestData} interface.
 */
public class DefaultSignatureActivationRequestData implements SignatureActivationRequestData {

  /** For serializing. */
  private static final long serialVersionUID = -1520960669328609013L;

  /** The sign request ID. */
  private final String signRequestId;

  /** The number of documents that are to be signed. */
  private final int documentCount;

  /** Whether sending the SAD request is mandatory/required. */
  private final boolean required;

  /**
   * Constructor.
   *
   * @param signRequestId the sign request ID
   * @param documentCount the number of documents that are to be signed
   * @param required whether sending a SAD request is mandatory
   */
  public DefaultSignatureActivationRequestData(
      @Nonnull final String signRequestId, final int documentCount, final boolean required) {
    this.signRequestId = Objects.requireNonNull(signRequestId, "signRequestId must not be null");
    this.documentCount = documentCount;
    this.required = required;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getSignRequestId() {
    return this.signRequestId;
  }

  /** {@inheritDoc} */
  @Override
  public int getDocumentCount() {
    return this.documentCount;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRequired() {
    return this.required;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.signRequestId, this.documentCount, this.required);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(@Nullable final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultSignatureActivationRequestData)) {
      return false;
    }
    final DefaultSignatureActivationRequestData other = (DefaultSignatureActivationRequestData) obj;
    return Objects.equals(this.signRequestId, other.signRequestId)
        && this.documentCount == other.documentCount
        && this.required == other.required;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String toString() {
    return String.format("sign-request-id='%s', document-count=%d, required=%s",
        this.signRequestId, this.documentCount, this.required);
  }

}
