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
package se.swedenconnect.signservice.signature.signer.crypto;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;

import java.io.IOException;
import java.util.Arrays;

/**
 * Provides functions to create and verify RSA Padded data according to PKCS#1 version 1.5
 *
 * <p>
 * Note that PKCS#1 padding includes the digest algorithm as BER encoded
 * AlgorithmIdentifier. This means that there are multiple ways to encode the same hash
 * algorithm as 1) BER encoding is not distinguished and 2) the encoding of certain hash
 * algorithms may differ. One example of this is whether the absent parameters of SHA256
 * that MUST be absent, in some cases are implemented as a NULL value resulting in
 * different encoding
 * </p>
 * <p>
 * For this reason, proper validation always require that the decrypted padded data is
 * inspected and parsed to extract the hash algorithm OID as well asn the encrypted hash
 * value
 * </p>
 */
@Slf4j
public class PKCS1V15Padding {

  /**
   * Prepare the PKCS#1 version 1.5 padding of the hash of the data to be signed.
   *
   * @param digestAlgo signature hash algorithm
   * @param hashValue hash value of the data to be signed
   * @return padded data to be signed hash
   * @throws IOException illegal input data
   */
  public static byte[] getRSAPkcs1DigestInfo(@NonNull final MessageDigestAlgorithm digestAlgo,
    @NonNull final byte[] hashValue) throws IOException {
    final ASN1EncodableVector digestInfoSeq = new ASN1EncodableVector();
    final AlgorithmIdentifier algoId = digestAlgo.getAlgorithmIdentifier();
    digestInfoSeq.add(algoId);
    digestInfoSeq.add(new DEROctetString(hashValue));
    return new DERSequence(digestInfoSeq).getEncoded("DER");
  }

  /**
   * Verifies that message digest value match PKCS#1 padded data
   *
   * @param paddedDigest PKCS#1 padded digest value
   * @param digest the digest value that should be verified against the PKCS#1 padded
   * digest
   * @param messageDigestAlgorithm the message digest algorithm that was used to create
   * the message digest value
   * @return true on match otherwise false
   * @throws IOException error in input data
   */
  public static boolean verifyMessageDigest(@NonNull final byte[] paddedDigest, @NonNull final byte[] digest,
    @NonNull final MessageDigestAlgorithm messageDigestAlgorithm) throws IOException {

    try {
      final ASN1InputStream asn1InputStream = new ASN1InputStream(paddedDigest);
      final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());
      final AlgorithmIdentifier hashAlgorithmIdentifier = AlgorithmIdentifier
        .getInstance(asn1Sequence.getObjectAt(0));
      final ASN1ObjectIdentifier paddedDigestAlgoId = hashAlgorithmIdentifier.getAlgorithm();
      final ASN1OctetString octetString = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));
      byte[] paddedDigestValue = octetString.getOctets();

      boolean digestMatch = Arrays.equals(paddedDigestValue, digest);
      boolean hashAlgoMatch = messageDigestAlgorithm.getAlgorithmIdentifier().getAlgorithm()
        .equals(paddedDigestAlgoId);

      if (!digestMatch) {
        log.debug("Digest value does not match padded data");
        return false;
      }
      if (!hashAlgoMatch) {
        log.debug("Hash algorithm in padded data does not match specified digest algorithm");
        return false;
      }
      return true;
    }
    catch (Exception ex) {
      throw new IOException("Failed to process padding verification data", ex);
    }
  }

}
