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
package se.swedenconnect.signservice.signature.signhandler.impl;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSigner;
import se.swedenconnect.signservice.signature.signhandler.crypto.EcdsaSigValue;
import se.swedenconnect.signservice.signature.signhandler.crypto.PkCrypto;

import java.security.PrivateKey;
import java.security.SignatureException;

/**
 * Implementation of EC signer for calculating the EC signature values
 */
@Slf4j
public class SignServiceECSigner implements SignServiceSigner {

  /** Signature type for signatures created by this signer */
  private final SignatureType signatureType;

  public SignServiceECSigner(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  /** {@inheritDoc} */
  @Override public byte[] sign(final byte[] toBeSignedBytes, final PrivateKey privateKey, final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    try {
      final EcdsaSigValue ecdsaSigVal = PkCrypto.ecdsaSignData(toBeSignedBytes, privateKey, signatureAlgorithm);
      switch (signatureType) {
      case XML:
        return ecdsaSigVal.toByteArray();
      case PDF:
        return ecdsaSigVal.getDEREncodedSigValue();
      default:
        throw new IllegalArgumentException("Unsupported signature type " + signatureType);
      }
    } catch (Exception ex) {
      throw (ex instanceof SignatureException) ? (SignatureException) ex : new SignatureException(ex);
    }
  }
}
