package se.swedenconnect.signservice.signature.impl.sign.impl;

import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.impl.StaticAlgorithmRegistry;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.sign.SignServiceSigner;
import se.swedenconnect.signservice.signature.impl.sign.SignServiceSignerProvider;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSignServiceSignerProvider implements SignServiceSignerProvider {
  /**
   * Get a sign service signer for a given signature algorithm and signature type
   *
   * @param signatureAlgorithm the signature algorithm to use
   * @param signatureType      the type of signature that is being created (typically, XML, PDF or JSON)
   * @return {@link SignServiceSigner} for the given algorithm and signature type
   */
  @Override public SignServiceSigner getSigner(String signatureAlgorithm, SignatureType signatureType) {

    StaticAlgorithmRegistry.getDefaultSignatureAlgorithms();

    return null;
  }
}
