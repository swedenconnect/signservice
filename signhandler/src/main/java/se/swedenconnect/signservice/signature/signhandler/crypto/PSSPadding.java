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
package se.swedenconnect.signservice.signature.signhandler.crypto;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSA-PSS as described in PKCS# 1 v 2.1.
 * <p>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 * </p>
 */
public class PSSPadding {
  static final public byte TRAILER_IMPLICIT = (byte) 0xBC;

  private final Digest contentDigest;
  private final Digest mgfDigest;
  private SecureRandom random;

  private final int modulusBits;
  private final int hLen;
  private final int mgfhLen;
  private final boolean sSet;
  private final int sLen;
  private int emBits;
  private final byte[] salt;
  private final byte[] mDash;
  private byte[] block;
  private final byte trailer;

  /**
   * Basic constructor.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use.
   */
  public PSSPadding(
    final int modulusBits,
    final Digest digest) {
    this(modulusBits, digest, digest.getDigestSize(), TRAILER_IMPLICIT);
  }

  /**
   * Basic constructor.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use.
   * @param sLen the length of the salt to use (in bytes)
   */
  public PSSPadding(
    final int modulusBits,
    final Digest digest,
    final int sLen) {
    this(modulusBits, digest, sLen, TRAILER_IMPLICIT);
  }

  /**
   * Constructor.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use.
   * @param sLen the length of the salt to use (in bytes)
   * @param trailer the trailer byte to use
   */
  public PSSPadding(
    final int modulusBits,
    final Digest digest,
    final int sLen,
    final byte trailer) {
    this(modulusBits, digest, digest, sLen, trailer);
  }

  /**
   * Constructor.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param contentDigest the digest to use for content
   * @param mgfDigest the digest to use for MGF
   * @param sLen the length of the salt to use (in bytes)
   */
  public PSSPadding(
    final int modulusBits,
    final Digest contentDigest,
    final Digest mgfDigest,
    final int sLen) {
    this(modulusBits, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT);
  }

  /**
   * Constructor
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param contentDigest the digest to use for content
   * @param mgfDigest the digest to use for MGF
   * @param sLen the length of the salt to use (in bytes)
   * @param trailer the trailer byte to use
   */
  public PSSPadding(
    final int modulusBits,
    final Digest contentDigest,
    final Digest mgfDigest,
    final int sLen,
    final byte trailer) {
    this.modulusBits = modulusBits;
    this.contentDigest = contentDigest;
    this.mgfDigest = mgfDigest;
    this.hLen = contentDigest.getDigestSize();
    this.mgfhLen = mgfDigest.getDigestSize();
    this.sSet = false;
    this.sLen = sLen;
    this.salt = new byte[sLen];
    this.mDash = new byte[8 + sLen + hLen];
    this.trailer = trailer;
    init();
  }

  /**
   * Constructor with explicit salt value.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use
   * @param salt salt value
   */
  public PSSPadding(
    final int modulusBits,
    final Digest digest,
    final byte[] salt) {
    this(modulusBits, digest, digest, salt, TRAILER_IMPLICIT);
  }

  /**
   * Constructor with explicit salt and MGF hash.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param contentDigest the digest to use for content
   * @param mgfDigest the digest to use for MGF
   * @param salt salt value
   */
  public PSSPadding(
    final int modulusBits,
    final Digest contentDigest,
    final Digest mgfDigest,
    final byte[] salt) {
    this(modulusBits, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT);
  }

  /**
   * Constructor with explicit salt, MGF hash algorithm and trailer.
   *
   * @param modulusBits number of bits in RSA key modulus
   * @param contentDigest the digest to use for content
   * @param mgfDigest the digest to use for MGF
   * @param salt salt value
   * @param trailer the trailer byte to use
   */
  public PSSPadding(
    final int modulusBits,
    final Digest contentDigest,
    final Digest mgfDigest,
    final byte[] salt,
    final byte trailer) {
    this.modulusBits = modulusBits;
    this.contentDigest = contentDigest;
    this.mgfDigest = mgfDigest;
    this.hLen = contentDigest.getDigestSize();
    this.mgfhLen = mgfDigest.getDigestSize();
    this.sSet = true;
    this.sLen = salt.length;
    this.salt = salt;
    this.mDash = new byte[8 + sLen + hLen];
    this.trailer = trailer;
    init();
  }

  /**
   * Init pss padding.
   */
  private void init() {

    random = CryptoServicesRegistrar.getSecureRandom();
    emBits = modulusBits - 1;

    if (emBits < (8 * hLen + 8 * sLen + 9)) {
      throw new IllegalArgumentException("key too small for specified hash and salt lengths");
    }

    block = new byte[(emBits + 7) / 8];

    reset();
  }

  /**
   * clear possible sensitive data.
   */
  private void clearBlock(final byte[] block) {
    Arrays.fill(block, (byte) 0);
  }

  /**
   * update the internal digest with the byte b
   */
  public void update(final byte b) {
    contentDigest.update(b);
  }

  /**
   * update the internal digest with the byte array in.
   */
  public void update(final byte[] in) {
    contentDigest.update(in, 0, in.length);
  }

  /**
   * update the internal digest.
   *
   * @param in input
   * @param off offset from start
   * @param len length of data to copy from input
   */
  public void update(final byte[] in, final int off, final int len) {
    contentDigest.update(in, off, len);
  }

  /**
   * reset the internal state
   */
  public void reset() {
    contentDigest.reset();
  }

  /**
   * Generate a padded message for the data that has been loaded using the update() function.
   */
  public byte[] generateSignatureEncodedMessage() throws DataLengthException {
    contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

    if (sLen != 0) {
      if (!sSet) {
        random.nextBytes(salt);
      }

      System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
    }

    final byte[] h = new byte[hLen];

    contentDigest.update(mDash, 0, mDash.length);

    contentDigest.doFinal(h, 0);

    block[block.length - sLen - 1 - hLen - 1] = 0x01;
    System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

    byte[] dbMask = maskGeneratorFunction1(h, 0, h.length, block.length - hLen - 1);
    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

    block[block.length - 1] = trailer;

    final byte[] b = new byte[block.length];
    System.arraycopy(block, 0, b, 0, block.length);

    clearBlock(block);

    return b;
  }

  /**
   * return true if the internal state matches the encodedMessage. The encodedMessage is a pss padded hash value and is typically the
   * value obtained when performing raw decryption of an RSA-PSS signature value.
   *
   * @param encodedMessage encodedMessage to test
   * @return true if the encodedMessage is consistent with and verified by the PSS padding
   */
  public boolean verifySignatureEncodedMessage(final byte[] encodedMessage) {
    contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

    try {
      System.arraycopy(encodedMessage, 0, block, block.length - encodedMessage.length, encodedMessage.length);
    }
    catch (Exception e) {
      return false;
    }

    if (block[block.length - 1] != trailer) {
      clearBlock(block);
      return false;
    }

    byte[] dbMask = maskGeneratorFunction1(block, block.length - hLen - 1, hLen, block.length - hLen - 1);

    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    for (int i = 0; i != block.length - hLen - sLen - 2; i++) {
      if (block[i] != 0) {
        clearBlock(block);
        return false;
      }
    }

    if (block[block.length - hLen - sLen - 2] != 0x01) {
      clearBlock(block);
      return false;
    }

    if (sSet) {
      System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
    }
    else {
      System.arraycopy(block, block.length - sLen - hLen - 1, mDash, mDash.length - sLen, sLen);
    }

    contentDigest.update(mDash, 0, mDash.length);
    contentDigest.doFinal(mDash, mDash.length - hLen);

    for (int i = block.length - hLen - 1, j = mDash.length - hLen;
         j != mDash.length; i++, j++) {
      if ((block[i] ^ mDash[j]) != 0) {
        clearBlock(mDash);
        clearBlock(block);
        return false;
      }
    }

    clearBlock(mDash);
    clearBlock(block);

    return true;
  }

  /**
   * int to octet string.
   */
  private void ItoOSP(final int i, final byte[] sp) {
    sp[0] = (byte) (i >>> 24);
    sp[1] = (byte) (i >>> 16);
    sp[2] = (byte) (i >>> 8);
    sp[3] = (byte) (i);
  }

  /**
   * mask generator function, as described in PKCS1v2.
   */
  private byte[] maskGeneratorFunction1(final byte[] Z, final int zOff, final int zLen, final int length) {
    final byte[] mask = new byte[length];
    final byte[] hashBuf = new byte[mgfhLen];
    final byte[] C = new byte[4];
    int counter = 0;

    mgfDigest.reset();

    while (counter < (length / mgfhLen)) {
      ItoOSP(counter, C);

      mgfDigest.update(Z, zOff, zLen);
      mgfDigest.update(C, 0, C.length);
      mgfDigest.doFinal(hashBuf, 0);

      System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

      counter++;
    }

    if ((counter * mgfhLen) < length) {
      ItoOSP(counter, C);

      mgfDigest.update(Z, zOff, zLen);
      mgfDigest.update(C, 0, C.length);
      mgfDigest.doFinal(hashBuf, 0);

      System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
    }

    return mask;
  }
}
