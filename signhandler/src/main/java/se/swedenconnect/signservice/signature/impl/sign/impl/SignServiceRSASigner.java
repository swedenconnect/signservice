package se.swedenconnect.signservice.signature.impl.sign.impl;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.impl.sign.SignServiceSigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignServiceRSASigner implements SignServiceSigner {
  @Override public byte[] sign(byte[] toBeSignedBytes, PrivateKey privateKey, SignatureAlgorithm signatureAlgorithm)
    throws SignatureException {
    return new byte[0];
  }

  public static byte[] getRSAPkcs1DigestInfo(MessageDigestAlgorithm digestAlgo, byte[] hashValue) throws IOException {
    ASN1EncodableVector digestInfoSeq = new ASN1EncodableVector();
    AlgorithmIdentifier algoId = digestAlgo.getAlgorithmIdentifier();
    digestInfoSeq.add(algoId);
    digestInfoSeq.add(new DEROctetString(hashValue));
    return new DERSequence(digestInfoSeq).getEncoded("DER");
  }


}
