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
package se.swedenconnect.signservice.signature.impl;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.signature.AdESObject;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Default implementation of the {@link RequestedSignatureTask} interface.
 */
public class DefaultRequestedSignatureTask implements RequestedSignatureTask {

  /** For serializing. */
  private static final long serialVersionUID = -8961771197694209260L;

  /** Task ID. */
  private String taskId;

  /** Signature type. */
  private SignatureType signatureType;

  /** AdES type. */
  private AdESType adesType;

  /** AdES object. */
  private AdESObject adesObject;

  /** Processing rules URI. */
  private String processingRulesUri;

  /** The to-be-signed data. */
  private byte[] tbsData;

  /**
   * Default constructor.
   */
  public DefaultRequestedSignatureTask() {
  }

  /** {@inheritDoc} */
  @Override
  public String getTaskId() {
    return this.taskId;
  }

  /**
   * Assigns the task ID.
   *
   * @param taskId the task ID
   */
  public void setTaskId(final String taskId) {
    this.taskId = taskId;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  /**
   * Assigns the signature type.
   *
   * @param signatureType the signature type
   */
  public void setSignatureType(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  /**
   * Assigns the signature type.
   *
   * @param signatureType the signature type
   */
  public void setSignatureType(final String signatureType) {
    this.signatureType = signatureType != null ? SignatureType.fromType(signatureType) : null;
  }

  /** {@inheritDoc} */
  @Override
  public AdESType getAdESType() {
    return this.adesType;
  }

  /**
   * Assigns the AdES type.
   *
   * @param adesType the AdES type
   */
  public void setAdESType(final AdESType adesType) {
    this.adesType = adesType;
  }

  /**
   * Assigns the AdES type.
   * <p>
   * A value of "None" means that no AdES type is assigned.
   * </p>
   *
   * @param adesType the AdES type
   */
  public void setAdESType(final String adesType) {
    if (adesType == null || "None".equalsIgnoreCase(adesType)) {
      this.adesType = null;
    }
    else {
      for (final AdESType t : AdESType.values()) {
        if (t.name().equalsIgnoreCase(adesType)) {
          this.adesType = t;
          break;
        }
      }
      if (this.adesType == null) {
        throw new IllegalArgumentException(
            String.format("%s is not a valid AdESType", adesType));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public AdESObject getAdESObject() {
    return this.adesObject;
  }

  /**
   * Assigns the AdES object.
   *
   * @param adesObject the AdES object
   */
  public void setAdESObject(final AdESObject adesObject) {
    this.adesObject = adesObject;
  }

  /** {@inheritDoc} */
  @Override
  public String getProcessingRulesUri() {
    return this.processingRulesUri;
  }

  /**
   * Assigns the processing rules URI.
   *
   * @param uri URI for a processing rule
   */
  public void setProcessingRulesUri(final String uri) {
    this.processingRulesUri = uri;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getTbsData() {
    return this.tbsData != null ? this.tbsData.clone() : null;
  }

  /**
   * Assigns the data-to-be signed.
   *
   * @param tbsData the to-be-signed data
   */
  public void setTbsData(final byte[] tbsData) {
    this.tbsData = tbsData != null ? tbsData.clone() : null;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(this.tbsData);
    result = prime * result
        + Objects.hash(this.adesObject, this.adesType, this.processingRulesUri,
            this.signatureType, this.taskId);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof RequestedSignatureTask)) {
      return false;
    }
    final RequestedSignatureTask other = (RequestedSignatureTask) obj;
    return Objects.equals(this.adesObject, other.getAdESObject()) && this.adesType == other.getAdESType()
        && Objects.equals(this.processingRulesUri, other.getProcessingRulesUri())
        && this.signatureType == other.getSignatureType()
        && Objects.equals(this.taskId, other.getTaskId()) && Arrays.equals(this.tbsData, other.getTbsData());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "task-id='%s', signature-type='%s', ades-type='%s', ades-object=[%s], processing-rules-uri='%s', "
            + "tbs-data=[%d bytes]",
        this.taskId, this.signatureType, Optional.ofNullable(this.adesType).map(AdESType::toString).orElse("None"),
        this.adesObject, this.processingRulesUri, this.tbsData != null ? this.tbsData.length : 0);
  }

}
