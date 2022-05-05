package se.swedenconnect.signservice.signature.impl.sign.impl;

import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.sign.SignServiceSigner;
import se.swedenconnect.signservice.signature.impl.sign.process.EcdsaSigValue;
import se.swedenconnect.signservice.signature.impl.sign.process.PkCrypto;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;

/**
 * Implementation of EC signer for calculating the EC signature values
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignServiceECSigner implements SignServiceSigner {

  private final SignatureType signatureType;

  public SignServiceECSigner(SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  @Override public byte[] sign(byte[] toBeSignedBytes, PrivateKey privateKey, SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    try {
      EcdsaSigValue ecdsaSigVal = PkCrypto.ecdsaSignData(toBeSignedBytes, privateKey, signatureAlgorithm);

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
