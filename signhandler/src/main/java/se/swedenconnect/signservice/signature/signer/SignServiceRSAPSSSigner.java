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
package se.swedenconnect.signservice.signature.signer;

import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.util.Objects;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.RSAPSSSignatureAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.signer.crypto.PSSPadding;
import se.swedenconnect.signservice.signature.signer.crypto.PkCrypto;

/**
 * Signer for creating RSA signatures using RSA-PSS (Probabilistic Signature Scheme) according to PKCS#1 v 2.1
 */
@Slf4j
public class SignServiceRSAPSSSigner implements SignServiceSigner {

  /** {@inheritDoc} */
  @Override
  public byte[] sign(@Nonnull final byte[] toBeSignedBytes, @Nonnull final PrivateKey privateKey,
      @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    if (toBeSignedBytes == null) {
      throw new SignatureException("bytes to be signed must not be null");
    }

    Objects.requireNonNull(privateKey, "privateKey must not be null");
    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm must not be null");

    if (!(signatureAlgorithm instanceof RSAPSSSignatureAlgorithm)) {
      throw new SignatureException("The specified algorithm is not an RSA PSS algorithm");
    }

    try {
      final Digest messageDigestFunction = DigestFactory.getDigest(
          signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
      final int modLen = ((RSAKey) privateKey).getModulus().bitLength();
      final PSSPadding pssPadding = new PSSPadding(modLen, messageDigestFunction);
      pssPadding.update(toBeSignedBytes);
      final byte[] emBytes = pssPadding.generateSignatureEncodedMessage();
      return PkCrypto.rsaSignEncodedMessage(emBytes, privateKey);
    }
    catch (Exception ex) {
      log.debug("Error creating RSA signature with algorithm {}", signatureAlgorithm, ex);
      throw new SignatureException(ex);
    }
  }
}
