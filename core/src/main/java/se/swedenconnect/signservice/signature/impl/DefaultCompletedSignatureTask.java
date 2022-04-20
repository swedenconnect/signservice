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
package se.swedenconnect.signservice.signature.impl;

import java.util.Arrays;
import java.util.Objects;

import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;

/**
 * Default implementation of the {@link CompletedSignatureTask} interface.
 */
public class DefaultCompletedSignatureTask extends DefaultRequestedSignatureTask implements CompletedSignatureTask {

  /** For serializing. */
  private static final long serialVersionUID = -2528235843629227296L;

  /** The signature bytes. */
  private byte[] signature;

  /** The signature algorithm URI. */
  private String signatureAlgorithmUri;

  /**
   * Default constructor.
   */
  public DefaultCompletedSignatureTask() {
    super();
  }

  /**
   * Constructor creating the task given a requested task.
   *
   * @param requestedSignatureTask a requested signature task
   */
  public DefaultCompletedSignatureTask(final RequestedSignatureTask requestedSignatureTask) {
    this();
    Objects.requireNonNull(requestedSignatureTask, "requestedSignatureTask must not be null");

    this.setTaskId(requestedSignatureTask.getTaskId());
    this.setSignatureType(requestedSignatureTask.getSignatureType());
    this.setAdESType(requestedSignatureTask.getAdESType());
    this.setAdESObject(requestedSignatureTask.getAdESObject());
    this.setProcessingRulesUri(requestedSignatureTask.getProcessingRulesUri());
    this.setTbsData(requestedSignatureTask.getTbsData());
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getSignature() {
    return this.signature != null ? this.signature.clone() : null;
  }

  /**
   * Assigns the signature bytes.
   *
   * @param signature the signature bytes
   */
  public void setSignature(final byte[] signature) {
    this.signature = signature != null ? signature.clone() : null;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureAlgorithmUri() {
    return this.signatureAlgorithmUri;
  }

  /**
   * Assigns the signature algorithm URI.
   *
   * @param signatureAlgorithmUri the signature algorithm URI
   */
  public void setSignatureAlgorithmUri(final String signatureAlgorithmUri) {
    this.signatureAlgorithmUri = signatureAlgorithmUri;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Arrays.hashCode(this.signature);
    result = prime * result + Objects.hash(this.signatureAlgorithmUri);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (!(obj instanceof CompletedSignatureTask)) {
      return false;
    }
    final CompletedSignatureTask other = (CompletedSignatureTask) obj;
    return Arrays.equals(this.signature, other.getSignature())
        && Objects.equals(this.signatureAlgorithmUri, other.getSignatureAlgorithmUri());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, signature=[%d bytes], signature-algorithm-uri='%s'", super.toString(),
        this.signature != null ? this.signature.length : 0, this.signatureAlgorithmUri);
  }

}
