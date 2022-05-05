/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package se.swedenconnect.signservice.signature.impl.sign.process;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.Comparator;

/**
 * Public key crypto implementations used to generate signature values
 */
public class PkCrypto {

    /**
     * Decrypts data with RSA using the RSA public key (used in signature verification process)
     * @param data RSA signature (RSA encrypted block) to be decrypted
     * @param pubKey public key for decryption
     * @return decrypted data
     * @throws NoSuchAlgorithmException unsupported algorithm
     * @throws NoSuchPaddingException unsupported padding
     * @throws InvalidKeyException invalid key
     * @throws IllegalBlockSizeException illegal block size
     * @throws BadPaddingException bad padding
     */
    public static byte[] rsaVerify(byte[] data, PublicKey pubKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;
    }

    /**
     * Sign data (encrypt) using RSA with PKCS#1 version 1.5 padding
     * @param data data to be encrypted (signed)
     * @param privateKey the private encryption key
     * @return encrypted RSA data
     * @throws NoSuchAlgorithmException unsupported algorithm
     * @throws NoSuchPaddingException unsupported padding
     * @throws InvalidKeyException invalid key
     * @throws IllegalBlockSizeException illegal block size
     * @throws BadPaddingException bad padding
     */
    public static byte[] rsaSign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * Raw RSA encryption of data that has been prepared with padding for RSA encryption
     * @param data preformatted data to be encrypted as provided
     * @param privKey private RSA key
     * @return encrypted data
     * @throws NoSuchAlgorithmException unsupported algorithm
     * @throws NoSuchPaddingException unsupported padding
     * @throws InvalidKeyException invalid key
     * @throws IllegalBlockSizeException illegal block size
     * @throws BadPaddingException bad padding
     */
    public static byte[] rsaSignEncodedMessage(byte[] data, PrivateKey privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(data);
    }

    /**
     *
     * @param digest
     * @param signature
     * @param pubKey
     * @return
     * @throws InvalidKeyException
     */
    public static boolean ecdsaVerifyDigest(byte[] digest, EcdsaSigValue signature, PublicKey pubKey) throws InvalidKeyException {
        ECDSASigner ecdsa = new ECDSASigner();
        CipherParameters param = ECUtil.generatePublicKeyParameter(pubKey);
        ecdsa.init(false, param);
        return ecdsa.verifySignature(digest, signature.getR(), signature.getS());
    }

    public static EcdsaSigValue ecdsaSignData(byte[] data, PrivateKey privKey, Algorithm sigAlgo) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException {
        Signature ecdsaSigner = Signature.getInstance(sigAlgo.getJcaName(), "BC");
        ecdsaSigner.initSign(privKey, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes()));
        ecdsaSigner.update(data);
        byte[] asn1SignatureBytes = ecdsaSigner.sign();
        ASN1InputStream asn1SignatureIs = new ASN1InputStream(asn1SignatureBytes);
        return EcdsaSigValue.getInstance(asn1SignatureIs);
    }

    public static boolean ecdsaVerifySignedData(byte[] data, EcdsaSigValue signature, PublicKey pubKey, MessageDigestAlgorithm digestAlgo, AlgorithmRegistry algorithmRegistry) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Algorithm sigAlgo = getAlgorithmFromTypeAndDigestMethod(digestAlgo, "EC", algorithmRegistry);
        EcdsaSigValue sigVal = EcdsaSigValue.getInstance(signature);
        byte[] asn1Signature = sigVal.toASN1Object().getEncoded();
        Signature ecdsaSigner = Signature.getInstance(sigAlgo.getJcaName(), "BC");
        ecdsaSigner.initVerify(pubKey);
        ecdsaSigner.update(data);
        return ecdsaSigner.verify(asn1Signature);
    }

    public static Algorithm getAlgorithmFromTypeAndDigestMethod(MessageDigestAlgorithm digestAlgo, String keyType, AlgorithmRegistry algorithmRegistry) {
        return algorithmRegistry.getAlgorithms(algorithm -> algorithm instanceof SignatureAlgorithm)
          .stream()
          .map(algorithm -> (SignatureAlgorithm) algorithm)
          .filter(algorithm -> algorithm.getKeyType().equalsIgnoreCase(keyType))
          .filter(algorithm -> algorithm.getMessageDigestAlgorithm().getAlgorithmIdentifier().equals(digestAlgo.getAlgorithmIdentifier()))
          .min(Comparator.comparingInt(Algorithm::getOrder))
          .orElse(null);
    }
}
