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
package se.swedenconnect.signservice.protocol.dss;

import java.io.Serial;
import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.idsec.signservice.dss.DSSStatusCodes;
import se.swedenconnect.schemas.dss_1_0.InternationalStringType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.protocol.SignResponseResult;

/**
 * The DSS implementation of the {@link SignResponseResult} interface.
 */
class DssSignResponseResult implements SignResponseResult {

  /** For serialization. */
  @Serial
  private static final long serialVersionUID = -1342465930360409621L;

  /** Corresponds to the dss:ResultMajor element. */
  private String resultMajor;

  /** Corresponds to the dss:ResultMinor element. */
  private String resultMinor;

  /** Corresponds to the dss:ResultMessage message. */
  private String resultMessage;

  /**
   * Constructor creating a successful response result.
   */
  public DssSignResponseResult() {
    this.resultMajor = DSSStatusCodes.DSS_SUCCESS;
  }

  /**
   * Constructor creating a response result based on the supplied {@link SignServiceError} object.
   *
   * @param error the error
   */
  public DssSignResponseResult(final SignServiceError error) {
    this.resultMessage = error.getMessage();

    switch (error.getErrorCode()) {
    case AUTHN_FAILURE:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_AUTHN_FAILED;
      break;
    case SECURITY_VIOLATION:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_SECURITY_VIOLATION;
      break;
    case AUTHN_SIGNMESSAGE_NOT_DISPLAYED:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_RESPONDER_ERROR_SIGMESSAGE_ERROR;
      break;
    case AUTHN_UNSUPPORTED_AUTHNCONTEXT:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_REQUESTER_ERROR_UNSUPPORTED_LOA;
      break;
    case AUTHN_USER_CANCEL:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_USER_CANCEL;
      break;
    case AUTHN_USER_MISMATCH:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_REQUESTER_ERROR_USER_MISMATCH;
      break;
    case REQUEST_EXPIRED:
      this.resultMajor = DSSStatusCodes.DSS_REQUESTER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_REQUESTER_ERROR_REQUEST_EXPIRED;
      break;
    case REQUEST_INCORRECT:
      this.resultMajor = DSSStatusCodes.DSS_REQUESTER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_REQUESTER_NOT_SUPPORTED;
      break;
    case KEY_GENERATION_FAILED:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_RESPONDER_ERROR_KEY_LOOKUP_FAILED;
      break;
    case CERT_ISSUANCE_FAILED:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_RESPONDER_ERROR_GENERAL_ERROR;
      break;
    case INTERNAL_ERROR:
      this.resultMajor = DSSStatusCodes.DSS_RESPONDER_ERROR;
      this.resultMinor = DSSStatusCodes.DSS_MINOR_RESPONDER_ERROR_GENERAL_ERROR;
      break;
    }
  }

  /**
   * Constructor creating a response object based on the DSS Result object.
   *
   * @param result DSS Result object
   */
  public DssSignResponseResult(final Result result) {
    this.resultMajor = result.getResultMajor();
    this.resultMinor = result.getResultMinor();
    this.resultMessage = Optional.ofNullable(result.getResultMessage())
        .map(InternationalStringType::getValue)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSuccess() {
    return DSSStatusCodes.DSS_SUCCESS.equals(this.resultMajor);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getErrorCode() {
    return this.resultMajor;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getMinorErrorCode() {
    return this.resultMinor;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getMessage() {
    return this.resultMessage;
  }

  /**
   * Assigns the status message.
   *
   * @param resultMessage the status message
   */
  public void setMessage(@Nullable final String resultMessage) {
    this.resultMessage = resultMessage;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.resultMajor, this.resultMessage, this.resultMinor);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final SignResponseResult other)) {
      return false;
    }
    return Objects.equals(this.resultMajor, other.getErrorCode())
        && Objects.equals(this.resultMinor, other.getMinorErrorCode())
        && Objects.equals(this.resultMessage, other.getMessage());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("result-major='").append(this.resultMajor).append("'");
    if (this.resultMinor != null) {
      sb.append(", result-minor='").append(this.resultMinor).append("'");
    }
    if (this.resultMessage != null) {
      sb.append(", result-message='").append(this.resultMessage).append("'");
    }
    return sb.toString();
  }

}
