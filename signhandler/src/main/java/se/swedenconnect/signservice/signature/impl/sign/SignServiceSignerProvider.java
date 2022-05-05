package se.swedenconnect.signservice.signature.impl.sign;

import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignServiceSignerProvider {

  /**
   * Get a sign service signer for a given signature algorithm and signature type
   * @param signatureAlgorithm the signature algorithm to use
   * @param signatureType the type of signature that is being created (typically, XML, PDF or JSON)
   * @return {@link SignServiceSigner} for the given algorithm and signature type
   */
  SignServiceSigner getSigner(String signatureAlgorithm, SignatureType signatureType);

}
