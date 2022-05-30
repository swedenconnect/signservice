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
package se.swedenconnect.signservice.authn.saml;

import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;

/**
 * A utility class for working with SAML {@link Status} objects.
 */
public class SamlStatus {

  /** The status code for cancel (defined by the Swedish eID framework). */
  public static final String CANCEL_STATUS_CODE = "http://id.elegnamnden.se/status/1.0/cancel";

  /** The status object. */
  @Nonnull
  private final Status status;

  /**
   * Constructor.
   *
   * @param status the status object
   */
  public SamlStatus(@Nonnull final Status status) {
    this.status = Objects.requireNonNull(status, "status must not be null");
  }

  /**
   * Gets the main status code.
   *
   * @return the main status code
   */
  @Nullable
  public String getMainStatusCode() {
    return Optional.ofNullable(this.status.getStatusCode())
        .map(StatusCode::getValue)
        .orElse(null);
  }

  /**
   * Gets the minor status code.
   *
   * @return the minor status code
   */
  @Nullable
  public String getMinorStatusCode() {
    return Optional.ofNullable(this.status.getStatusCode())
        .map(StatusCode::getStatusCode)
        .map(StatusCode::getValue)
        .orElse(null);
  }

  /**
   * Gets the status message.
   *
   * @return the status message
   */
  @Nullable
  public String getStatusMessage() {
    return Optional.ofNullable(this.status.getStatusMessage())
        .map(StatusMessage::getValue)
        .orElse(null);
  }

  /**
   * Gets the status message, and if no such message exists, returns the supplied {@code defaultMessage}
   *
   * @param defaultMessage the default message
   * @return the status message (or the default message if no message is available)
   */
  @Nonnull
  public String getStatusMessage(final String defaultMessage) {
    return Optional.ofNullable(this.status.getStatusMessage())
        .map(StatusMessage::getValue)
        .orElse(Objects.requireNonNull(defaultMessage, "defaultMessage must not be null"));
  }

  /**
   * Predicate telling whether this status object represents a cancelled operation.
   *
   * @return true if the status represents a cancelled operation and false otherwise
   */
  public boolean isCancel() {
    return CANCEL_STATUS_CODE.equals(this.getMinorStatusCode());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuffer sb = new StringBuffer("code='");
    sb.append(this.getMinorStatusCode()).append("'");
    final String minor = this.getMinorStatusCode();
    if (minor != null) {
      sb.append(", minor-code='").append(minor).append("'");
    }
    final String msg = this.getStatusMessage();
    if (msg != null) {
      sb.append(", message='").append(msg).append("'");
    }
    return sb.toString();
  }

}
