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
package se.swedenconnect.signservice.signature.impl;

import java.util.Arrays;
import java.util.Objects;

import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.signature.AdESObject;

/**
 * The default implementation of the {@link AdESObject} interface.
 */
public class DefaultAdESObject implements AdESObject {

  /** For serializing. */
  private static final long serialVersionUID = 8600449120280521232L;

  /** The signature ID. */
  private final String signatureId;

  /** The AdES object bytes. */
  private final byte[] objectBytes;

  /**
   * Constructor.
   *
   * @param signatureId the signature ID
   * @param objectBytes the object bytes
   */
  public DefaultAdESObject(final String signatureId, final byte[] objectBytes) {
    this.signatureId = signatureId;
    this.objectBytes = objectBytes != null ? objectBytes.clone() : null;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureId() {
    return this.signatureId;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getObjectBytes() {
    return this.objectBytes != null ? this.objectBytes.clone() : null;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(this.objectBytes);
    result = prime * result + Objects.hash(this.signatureId);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof AdESObject)) {
      return false;
    }
    final AdESObject other = (AdESObject) obj;
    return Arrays.equals(this.objectBytes, other.getObjectBytes())
        && Objects.equals(this.signatureId, other.getSignatureId());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("signature-id='%s', object-bytes=[%d bytes]",
        this.signatureId, this.objectBytes != null ? this.objectBytes.length : 0);
  }

}
