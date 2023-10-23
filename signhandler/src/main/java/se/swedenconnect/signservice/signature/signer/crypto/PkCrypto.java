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
package se.swedenconnect.signservice.signature.signer.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Comparator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;

/**
 * Public key crypto implementations used to generate signature values
 */
public class PkCrypto {

  /**
   * Sign data (encrypt) using RSA. Default method when signing data that is prepared
   * according to PKCS#1 v1.5
   *
   * @param data data to be encrypted (signed)
   * @param privateKey the private encryption key
   * @return encrypted RSA data
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchPaddingException unsupported padding
   * @throws InvalidKeyException invalid key
   * @throws IllegalBlockSizeException illegal block size
   * @throws BadPaddingException bad padding
   */
  public static byte[] rsaSign(final byte[] data, final PrivateKey privateKey) throws NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    final Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    return cipher.doFinal(data);
  }

  /**
   * Decrypts data with RSA using the RSA public key (used in signature verification
   * process)
   *
   * @param data RSA signature (RSA encrypted block) to be decrypted
   * @param pubKey public key for decryption
   * @return decrypted data
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchPaddingException unsupported padding
   * @throws InvalidKeyException invalid key
   * @throws IllegalBlockSizeException illegal block size
   * @throws BadPaddingException bad padding
   */
  public static byte[] rsaVerify(final byte[] data, final PublicKey pubKey) throws NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    final Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, pubKey);
    return cipher.doFinal(data);
  }

  /**
   * Raw RSA encryption of data
   *
   * @param data preformatted data to be encrypted as provided
   * @param privKey private RSA key
   * @return encrypted data
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchPaddingException unsupported padding
   * @throws InvalidKeyException invalid key
   * @throws IllegalBlockSizeException illegal block size
   * @throws BadPaddingException bad padding
   */
  public static byte[] rsaSignEncodedMessage(final byte[] data, final PrivateKey privKey)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException {
    final Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, privKey);
    return cipher.doFinal(data);
  }

  /**
   * Raw decrypts data with RSA using the RSA public key disregaring any padding
   * structrue
   *
   * @param data RSA signature (RSA encrypted block) to be decrypted
   * @param pubKey public key for decryption
   * @return decrypted data
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchPaddingException unsupported padding
   * @throws InvalidKeyException invalid key
   * @throws IllegalBlockSizeException illegal block size
   * @throws BadPaddingException bad padding
   */
  public static byte[] rsaVerifyEncodedMessage(final byte[] data, final PublicKey pubKey)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException {
    final Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, pubKey);
    return cipher.doFinal(data);
  }

  /**
   * Verify ECDSA signature value against a signed digest value
   *
   * @param digest signed digest value
   * @param signature signature value
   * @param pubKey public validation key
   * @return true if the digest can be validated using the public validation key
   * @throws InvalidKeyException the validation key is invalid
   * @throws IOException invalid input data
   */
  public static boolean ecdsaVerifyDigest(final byte[] digest, final EcdsaSigValue signature, final PublicKey pubKey)
    throws InvalidKeyException, IOException {
    try {
      final ECDSASigner ecdsa = new ECDSASigner();
      final CipherParameters param = ECUtil.generatePublicKeyParameter(pubKey);
      ecdsa.init(false, param);
      return ecdsa.verifySignature(digest, signature.getR(), signature.getS());
    }
    catch (InvalidKeyException ex) {
      throw ex;
    }
    catch (Exception ex) {
      throw new IOException(ex);
    }
  }

  /**
   * Sign data using ECDSA
   *
   * @param data data to be signed
   * @param privKey private signing key
   * @param sigAlgo signature algorithm
   * @return signature value
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchProviderException unsupported crypto provider
   * @throws InvalidKeyException invalid key
   * @throws SignatureException failure to generate signature value
   * @throws IOException bad input data
   */
  public static EcdsaSigValue ecdsaSignData(final byte[] data, final PrivateKey privKey, final Algorithm sigAlgo)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException,
    IOException {
    final Signature ecdsaSigner = Signature.getInstance(sigAlgo.getJcaName(), "BC");
    ecdsaSigner.initSign(privKey, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes()));
    ecdsaSigner.update(data);
    final byte[] asn1SignatureBytes = ecdsaSigner.sign();
    ASN1InputStream asn1SignatureIs = new ASN1InputStream(asn1SignatureBytes);
    return EcdsaSigValue.getInstance(asn1SignatureIs);
  }

  /**
   * Verify signed data against an ECDSA signature value
   *
   * @param data signed data
   * @param signature signature value
   * @param pubKey public verification key
   * @param digestAlgo digest algorithm used in signing process
   * @param algorithmRegistry algorithm registry holding supported algorithms
   * @return true if the provided data can be verified by the proved signature using the
   * provided public key
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws NoSuchProviderException unsupported crypto provider
   * @throws InvalidKeyException invalid key
   * @throws SignatureException failure to generate signature value
   * @throws IOException bad input data
   */
  public static boolean ecdsaVerifySignedData(final byte[] data, final EcdsaSigValue signature,
    final PublicKey pubKey, final MessageDigestAlgorithm digestAlgo, final AlgorithmRegistry algorithmRegistry)
    throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
    SignatureException {
    final Algorithm sigAlgo = getAlgorithmFromTypeAndDigestMethod(digestAlgo, "EC", algorithmRegistry);
    final EcdsaSigValue sigVal = EcdsaSigValue.getInstance(signature);
    final byte[] asn1Signature = sigVal.toASN1Object().getEncoded();
    final Signature ecdsaSigner = Signature.getInstance(sigAlgo.getJcaName(), "BC");
    ecdsaSigner.initVerify(pubKey);
    ecdsaSigner.update(data);
    return ecdsaSigner.verify(asn1Signature);
  }

  /**
   * Get the signature algorithm supported by a specific key type and digest algorithm
   *
   * @param digestAlgo signature digest algorithm
   * @param keyType key type
   * @param algorithmRegistry algorithm registry holding supported algorithms
   * @return signature algorithm, or null if no matching algorithm could be found
   */
  public static Algorithm getAlgorithmFromTypeAndDigestMethod(final MessageDigestAlgorithm digestAlgo,
    final String keyType, final AlgorithmRegistry algorithmRegistry) {
    return algorithmRegistry.getAlgorithms(algorithm -> algorithm instanceof SignatureAlgorithm).stream()
      .map(algorithm -> (SignatureAlgorithm) algorithm)
      .filter(algorithm -> algorithm.getKeyType().equalsIgnoreCase(keyType))
      .filter(algorithm -> algorithm.getMessageDigestAlgorithm().getAlgorithmIdentifier()
        .equals(digestAlgo.getAlgorithmIdentifier()))
      .min(Comparator.comparingInt(Algorithm::getOrder)).orElse(null);
  }

}
