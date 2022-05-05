package se.swedenconnect.signservice.signature.impl.sign.process;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.impl.MessageDigestAlgorithmImpl;
import se.swedenconnect.security.algorithms.impl.SignatureAlgorithmImpl;
import se.swedenconnect.signservice.signature.impl.sign.impl.SignServiceRSASigner;
import se.swedenconnect.signservice.signature.impl.testutils.TestUtils;

import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
class PkCryptoTest {

  static PublicKey publicRSAKey;
  static PrivateKey privateRSAKey;
  static PublicKey publicECKey;
  static PrivateKey privateECKey;
  static MessageDigestAlgorithm sha256;
  static Algorithm ecdsaSha256;

  @BeforeAll
  static void setUp() throws Exception {
    KeyStore rsaKs = KeyStore.getInstance("JKS");
    rsaKs.load(PkCryptoTest.class.getResourceAsStream("/rsa-signer.jks"), "Test1234".toCharArray());
    publicRSAKey = rsaKs.getCertificate("sign").getPublicKey();
    privateRSAKey = (PrivateKey) rsaKs.getKey("sign", "Test1234".toCharArray());

    KeyStore ecKs = KeyStore.getInstance("JKS");
    ecKs.load(PkCryptoTest.class.getResourceAsStream("/ec-signer.jks"), "Test1234".toCharArray());
    publicECKey = ecKs.getCertificate("sign").getPublicKey();
    privateECKey = (PrivateKey) ecKs.getKey("sign", "Test1234".toCharArray());

    sha256 = MessageDigestAlgorithmImpl.builder(
      org.apache.xml.security.algorithms.MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256)
      .jcaName("SHA-256")
      .build();

    ecdsaSha256 = SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256)
      .keyType("EC")
      .jcaName("SHA256withECDSA")
      .joseAlgorithm(JWSAlgorithm.ES256)
      .messageDigestAlgorithm(sha256)
      .build();

    if (Security.getProvider("BC") == null){
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
  }

  @Test
  void rsaSigningTest() throws Exception {
    log.info("RSA sign and verify test");
    MessageDigest md = MessageDigest.getInstance(sha256.getJcaName());
    byte[] messageHash = md.digest("Data to be signed".getBytes(StandardCharsets.UTF_8));
    log.info("Message hash {}", Hex.toHexString(messageHash));
    byte[] tbsdr = SignServiceRSASigner.getRSAPkcs1DigestInfo(sha256, messageHash);
    log.info("Padded hash (PKCS#1 1.5 {}", Hex.toHexString(tbsdr));
    byte[] signatureBytes = PkCrypto.rsaSign(tbsdr, privateRSAKey);
    log.info("Signature bytes (RSA sign: \n{}", TestUtils.base64Print(signatureBytes, 74));
    byte[] decrypted = PkCrypto.rsaVerify(signatureBytes, publicRSAKey);
    log.info("Decrypted signature value: {}", Hex.toHexString(decrypted));

    ASN1InputStream asn1InputStream = new ASN1InputStream(decrypted);
    ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());
    ASN1OctetString octetString = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));

    assertArrayEquals(messageHash, octetString.getOctets());
    log.info("Decrypted value match");

    byte[] emSignHAsh = PkCrypto.rsaSignEncodedMessage(messageHash, privateRSAKey);
    log.info("Raw RSA signing message hash: \n{}", TestUtils.base64Print(emSignHAsh, 74));
    byte[] decryptedEmSigned = PkCrypto.rsaVerify(emSignHAsh, publicRSAKey);
    log.info("Decrypted raw signed signature value: {}", Hex.toHexString(decryptedEmSigned));

    assertArrayEquals(messageHash, decryptedEmSigned);
    log.info("Raw encrypted data verification succeeded");
  }

  @Test
  void ecdsaVerifyDigest() throws Exception {
    log.info("ECDSA sign and verify test");
    log.info("Signing string: \"Data to be signed\"");
    EcdsaSigValue ecdsaSigValue = PkCrypto.ecdsaSignData("Data to be signed".getBytes(StandardCharsets.UTF_8), privateECKey, ecdsaSha256);
    log.info("Concatenated signature bytes: \n{}", TestUtils.base64Print(ecdsaSigValue.toByteArray(), 74));
    log.info("DER encoded signature value: \n{}", TestUtils.base64Print(ecdsaSigValue.getDEREncodedSigValue(), 74));

    MessageDigest md = MessageDigest.getInstance(sha256.getJcaName());
    byte[] messageHash = md.digest("Data to be signed".getBytes(StandardCharsets.UTF_8));
    log.info("Message hash {}", Hex.toHexString(messageHash));

    boolean verified = PkCrypto.ecdsaVerifyDigest(messageHash, ecdsaSigValue, publicECKey);

    assertTrue(verified);
    log.info("EC signature verified");
  }

  @Test
  void getAlgorithmFromTypeAndDigestMethod() {
    log.info("Testing to derive algorithm from hash and key type");
    log.info("Getting algorithm for SHA-256 and EC");
    Algorithm algorithm = PkCrypto.getAlgorithmFromTypeAndDigestMethod(sha256, "EC", AlgorithmRegistrySingleton.getInstance());
    log.info("Found algorithm: {}", algorithm.getUri());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" , algorithm.getUri());
  }
}