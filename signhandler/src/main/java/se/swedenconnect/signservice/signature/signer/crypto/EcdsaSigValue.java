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

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * ECDSA Signature value
 */
@Slf4j
public class EcdsaSigValue implements ASN1Encodable {

	@Getter
	@Setter
	private static int[] supportedKeyLengths = new int[] { 160, 224, 256, 384, 521 };

	/**
	 * @return the R component of the ECDSA Signature */
	@Getter
	private final BigInteger r;

	/**
	 * @return the S component of the ECDSA Signature */
	@Getter
	private final BigInteger s;

	/**
	 * Creates an instance of ECDSA signature value
	 * @param obj signature value object as {@link ASN1TaggedObject}
	 * @param explicit indicate if the tagging is explicit
	 * @return ECDSA signature value
	 * @throws IOException invalid input
	 */
	public static EcdsaSigValue getInstance(@NonNull final ASN1TaggedObject obj, final boolean explicit)
			throws IOException {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	/**
	 * Creates an instance of ECDSA signature value
	 * @param obj signature value object as {@link EcdsaSigValue}, {@link ASN1Sequence} or
	 * {@link ASN1InputStream}
	 * @return ECDSA signature value
	 * @throws IOException invalid input
	 */
	public static EcdsaSigValue getInstance(@NonNull final Object obj) throws IOException {
		if (obj instanceof EcdsaSigValue) {
			return (EcdsaSigValue) obj;
		}
		if (obj instanceof ASN1Sequence) {
			return new EcdsaSigValue((ASN1Sequence) obj);
		}
		if (obj instanceof ASN1InputStream) {
			return new EcdsaSigValue(ASN1Sequence.getInstance(((ASN1InputStream) obj).readObject()));
		}

		throw new IOException("unknown object in factory: " + obj.getClass().getName());
	}

	/**
	 * Creates an instance of ECDSA signature value
	 * @param concatenatedRS concatenated bytes of the R and S signature value integers
	 * @return ECDSA signature value
	 * @throws IOException invalid input
	 */
	public static EcdsaSigValue getInstance(@NonNull final byte[] concatenatedRS) throws IOException {
		try {
			final BigInteger[] rsVals = getRSFromConcatenatedBytes(concatenatedRS);
			return new EcdsaSigValue(rsVals[0], rsVals[1]);
		}
		catch (Exception ex) {
			throw new IOException("Unable to parse concatenated RS data", ex);
		}
	}

	/**
	 * Creates an instance of ECDSA signature value
	 * @param r R component of the ECDSA signature
	 * @param s S component of the ECDSA signature
	 */
	public static EcdsaSigValue getInstance(@NonNull final BigInteger r, @NonNull final BigInteger s)
			throws IOException {
		return new EcdsaSigValue(r, s);
	}

	private EcdsaSigValue(final BigInteger r, final BigInteger s) {
		this.r = r;
		this.s = s;
	}

	private EcdsaSigValue(final ASN1Sequence obj) throws IOException {
		try {
			final Enumeration<?> e = obj.getObjects();

			r = ASN1Integer.getInstance(e.nextElement()).getValue();
			s = ASN1Integer.getInstance(e.nextElement()).getValue();
		}
		catch (Exception ex) {
			throw new IOException("Error creating ECDSA signature value from provided ASN1 sequence", ex);
		}
	}

	private static BigInteger[] getRSFromConcatenatedBytes(final byte[] concatenatedRS) {

		final int rLen, sLen;
		final int len = concatenatedRS.length;
		rLen = len / 2;
		sLen = rLen;

		final byte[] rBytes = new byte[rLen];
		final byte[] sBytes = new byte[sLen];

		System.arraycopy(concatenatedRS, 0, rBytes, 0, rLen);
		System.arraycopy(concatenatedRS, rLen, sBytes, 0, sLen);

		final BigInteger[] srArray = new BigInteger[2];
		srArray[0] = getBigInt(rBytes);
		srArray[1] = getBigInt(sBytes);

		return srArray;
	}

	/**
	 * @return the ASN.1 object of the signature value
	 */
	public DERSequence toASN1Object() {
		final ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(new ASN1Integer(r));
		v.add(new ASN1Integer(s));

		return new DERSequence(v);
	}

	/**
	 * Gets the bytes to be carried in an OCTET STRING to form the CMS signature value
	 * @return DER encoded bytes of the signature value ASN.1 SEQUENCE
	 * @throws IOException illegal signature value
	 */
	public byte[] getDEREncodedSigValue() throws IOException {
		return toASN1Object().getEncoded("DER");
	}

	/**
	 * Returns the concatenation of the bytes of r and s
	 * @return byte array representation of signature value
	 * @throws IOException illegal signature value
	 */
	public byte[] toByteArray() throws IOException {
		try {
			final int blockSize = getSigValueBlockSize();

			final byte[] rBytes = trimByteArray(r.toByteArray(), blockSize);
			final byte[] sBytes = trimByteArray(s.toByteArray(), blockSize);
			final byte[] rsBytes = new byte[rBytes.length + sBytes.length];
			System.arraycopy(rBytes, 0, rsBytes, 0, rBytes.length);
			System.arraycopy(sBytes, 0, rsBytes, rBytes.length, sBytes.length);

			return rsBytes;
		}
		catch (Exception ex) {
			throw new IOException("Illegal signature value", ex);
		}
	}

	/**
	 * Return the key length that represents the signature value block size. For EC 256
	 * bit key the block size is 256. For EC 521 bit key the block size is 528 (the bits
	 * of the full byte count that can contain the key).
	 *
	 * <p>
	 * Calculation of the block size take into account that the actual integer byte
	 * representation may be different than the block size/8. This is the case when the
	 * bytes representation of the integer is padded to avoid negative representation as
	 * well as the situation when the byte count is shorter since the actual integer is
	 * smaller than the allowed max size
	 * </p>
	 *
	 * <p>
	 * For this reason this implementation lists allowed key sizes supported by this
	 * implementation and present integers must fit these key sizes. A match is when the
	 * size without padding is an exact match or when the sum size difference between both
	 * integer byte count and 2 x the block size byte count is not grater than 4 bytes.
	 * </p>
	 * @return The block size of this signature value in bytes
	 * @throws IOException if the integer values does not fit the preset key lengths
	 */
	private int getSigValueBlockSize() throws IOException {
		final int rByteLen = getDataLength(r);
		final int sByteLen = getDataLength(s);

		return Arrays.stream(supportedKeyLengths).map(bitLength -> (int) Math.ceil((double) bitLength / 8))
				.filter(byteLength -> byteLength >= rByteLen && byteLength >= sByteLen)
				.filter(byteLength -> (2 * byteLength - (rByteLen + sByteLen)) < 4).findFirst()
				.orElseThrow(IOException::new);

	}

	/**
	 * Return the actual number of bytes representing the value of an integer not counting
	 * any padding bytes Since the bytes are derived form a BigInteger, the maximum number
	 * of present padding bytes is 1
	 * @param integer integer value
	 * @return number of data bytes representing the positive integer value
	 */
	private int getDataLength(final BigInteger integer) {
		final byte[] integerBytes = integer.toByteArray();
		if (integerBytes.length == 0) {
			return 0;
		}
		return integerBytes[0] == 0x00 ? integerBytes.length - 1 : integerBytes.length;
	}

	/**
	 * Trim the bytes of an integer to fit a predefined block length
	 * @param inpBytes the data bytes of a positive integer value
	 * @param blockSize block length in bytes
	 * @return trimmed bytes
	 */
	private static byte[] trimByteArray(final byte[] inpBytes, final int blockSize) {
		final int len = inpBytes.length;
		if (len == blockSize) {
			return inpBytes;
		}
		final byte[] trimmed = new byte[blockSize];

		if (len < blockSize) {
			int padCnt = blockSize - len;
			for (int i = 0; i < padCnt; i++) {
				trimmed[i] = 0x00;
				System.arraycopy(inpBytes, 0, trimmed, padCnt, len);
			}
		}

		if (len > blockSize) {
			int truncCnt = len - blockSize;
			System.arraycopy(inpBytes, truncCnt, trimmed, 0, len - truncCnt);
		}

		return trimmed;
	}

	/**
	 * Get the BigInteger value of a byte source representing a positive integer
	 * @param source byte data of positive integer that may or may not have a leading
	 * padding byte
	 * @return positive BigInteger value
	 */
	private static BigInteger getBigInt(final byte[] source) {
		final byte[] padded = new byte[source.length + 1];
		padded[0] = 0x00;
		System.arraycopy(source, 0, padded, 1, source.length);
		return new BigInteger(padded);
	}

	/**
	 * Returns the ASN1 object representation of this ECDSA signature value
	 * @return ASN1 object representation of this ECDSA signature value
	 */
	public ASN1Primitive toASN1Primitive() {
		return toASN1Object();
	}

}
