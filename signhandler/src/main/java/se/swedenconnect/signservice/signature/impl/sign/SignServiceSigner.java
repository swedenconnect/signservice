package se.swedenconnect.signservice.signature.impl.sign;

import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;

import java.security.PrivateKey;
import java.security.SignatureException;

/**
 * Interface for signature value creator
 */
public interface SignServiceSigner {

  byte[] sign(byte[] toBeSignedBytes, PrivateKey privateKey, SignatureAlgorithm signatureAlgorithm) throws SignatureException;

}
