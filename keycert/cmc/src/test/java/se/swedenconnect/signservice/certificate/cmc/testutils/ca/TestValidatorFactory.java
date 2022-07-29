/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.sigval.cert.chain.AbstractPathValidator;
import se.swedenconnect.sigval.cert.chain.impl.CertificatePathValidator;
import se.swedenconnect.sigval.cert.chain.impl.CertificatePathValidatorFactory;
import se.swedenconnect.sigval.cert.chain.impl.CertificateValidityCheckerFactory;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.CertificateValidityChecker;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLCacheImpl;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLDataLoader;
import se.swedenconnect.sigval.cert.validity.impl.BasicCertificateValidityChecker;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPCertificateVerifier;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPDataLoader;

import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Providing certificate validator for certificates issued by a CA provider
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestValidatorFactory {

  /**
   * Creates and returns the components of a certificate validator. These components are the actual certificate validator and the CRL cache
   * used by the certificate validator. The profiles regulate whether a certificate validator according the the profile should be responsive
   * or not.
   *
   * @param trustedCerts The list of trusted certificates trusted by this validator
   * @param profile profile determining the function of the validator
   * @param singleThreaded true to run the certificate validator in singlethreaded mode
   * @return Certificate validator components
   * @throws IOException On error
   * @throws CertificateException On error
   */
  public static CertValidatorComponents getCertificateValidator(List<X509Certificate> trustedCerts, ValidatorProfile profile, boolean singleThreaded)
    throws IOException, CertificateException {

    File crlCacheDir = new File(System.getProperty("user.dir"), "target/test/crl-cache");
    CRLCache crlCache = new CRLCacheImpl(crlCacheDir, 0, new TestCRLDataLoader(profile));

    StatusCheckingCertificateValidatorImpl certificateValidator = new StatusCheckingCertificateValidatorImpl(
      crlCache, null, trustedCerts.toArray(new X509Certificate[0]));
    certificateValidator.setCertificatePathValidatorFactory(
      new TestCertificatePathValidatorFactory(singleThreaded, profile));
    certificateValidator.setSingleThreaded(singleThreaded);
    return new CertValidatorComponents(certificateValidator, crlCache);
  }

  public static class TestCertificatePathValidatorFactory implements CertificatePathValidatorFactory {
    private final boolean singleThreaded;
    private final ValidatorProfile profile;

    public TestCertificatePathValidatorFactory(boolean singleThreaded, ValidatorProfile profile) {
      this.singleThreaded = singleThreaded;
      this.profile = profile;
    }

    @Override public AbstractPathValidator getPathValidator(X509Certificate targetCert, List<X509Certificate> chain,
      List<TrustAnchor> trustAnchors, CertStore certStore, CRLCache crlCache) {
      CertificatePathValidator pathValidator = new CertificatePathValidator(targetCert, chain, trustAnchors, certStore, crlCache);
      if (singleThreaded) {
        pathValidator.setSingleThreaded(true);
      }
      else {
        pathValidator.setMaxValidationSeconds(150);
      }
      pathValidator.setCertificateValidityCheckerFactory(new TestCertificateValidityCheckerFactory(profile));
      return pathValidator;
    }
  }

  public static class TestCertificateValidityCheckerFactory implements CertificateValidityCheckerFactory {
    private final ValidatorProfile profile;

    public TestCertificateValidityCheckerFactory(ValidatorProfile profile) {
      this.profile = profile;
    }

    @Override public CertificateValidityChecker getCertificateValidityChecker(X509Certificate certificate, X509Certificate issuer,
      CRLCache crlCache, PropertyChangeListener... propertyChangeListeners) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(certificate, issuer, crlCache,
        propertyChangeListeners);
      validityChecker.setSingleThreaded(true);
      validityChecker.getValidityCheckers().stream()
        .filter(vc -> vc instanceof OCSPCertificateVerifier)
        .map(vc -> (OCSPCertificateVerifier) vc)
        .forEach(ocspCertificateVerifier -> ocspCertificateVerifier.setOcspDataLoader(new TestOCSPDataLoader(profile)));
      return validityChecker;
    }
  }

  public static class TestOCSPDataLoader implements OCSPDataLoader {
    @Getter private String lastResponseB64;
    @Setter private boolean enforceUrlMatch = true;
    private final ValidatorProfile profile;

    public TestOCSPDataLoader(ValidatorProfile profile) {
      this.profile = profile;
    }

    @Override public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException {
      TestCAHolder caHolder = getTestCSCAService(ocspReq);
      TestCAService cscaService = caHolder.getCscaService();
      OCSPResponder ocspResponder = cscaService.getOCSPResponder();
      if (cscaService.getOCSPResponderURL().equals(url) || !enforceUrlMatch) {
        OCSPResp ocspResp = ocspResponder.handleRequest(
          OCSPRequest.getInstance(new ASN1InputStream(ocspReq.getEncoded()).readObject()));
        lastResponseB64 = Base64.toBase64String(ocspResp.getEncoded());
        switch (profile) {
        case NONE_RESPONSIVE:
          return null;
        default:
          return ocspResp;
        }
      }
      throw new IOException("Unable to get OCSP response on requested URL");
    }

    @SneakyThrows
    private TestCAHolder getTestCSCAService(OCSPReq ocspReq) {
      CertificateID certID = ocspReq.getRequestList()[0].getCertID();

      Map<TestCA, TestCAHolder> testCAHolderMap = TestServices.getTestCAs();
      Set<TestCA> testCAS = testCAHolderMap.keySet();
      for (TestCA testCa : testCAS) {
        TestCAHolder testCAHolder = testCAHolderMap.get(testCa);
        X509Certificate issuer = X509Utils.decodeCertificate(testCAHolder.getCscaService().getCaCertificate().getEncoded());
        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        CertificateID matchCertificateId = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuer), BigInteger.ONE);
        if (matchCertId(certID, matchCertificateId)) {
          return testCAHolder;
        }
      }
      return null;
    }

    private boolean matchCertId(CertificateID certID, CertificateID matchCertificateId) {
      boolean nameMatch = Arrays.equals(certID.getIssuerNameHash(), matchCertificateId.getIssuerNameHash());
      boolean keyMatch = Arrays.equals(certID.getIssuerKeyHash(), matchCertificateId.getIssuerKeyHash());
      return nameMatch && keyMatch;
    }
  }

  public static class TestCRLDataLoader implements CRLDataLoader {
    private final ValidatorProfile profile;

    public TestCRLDataLoader(ValidatorProfile profile) {
      this.profile = profile;
    }

    @Override public byte[] downloadCrl(String url, int connectTimeout, int readTimeout) throws IOException {
      if (url.startsWith(TestCAHolder.FILE_URL_PREFIX)) {
        String urlEncodedPath = url.substring(TestCAHolder.FILE_URL_PREFIX.length());
        String filePath = URLDecoder.decode(urlEncodedPath, StandardCharsets.UTF_8);
        File crlFile = new File(filePath);
        switch (profile) {
        case NONE_RESPONSIVE:
          return null;
        default:
          return FileUtils.readFileToByteArray(crlFile);
        }
      }
      throw new IOException("Illegal file path URL");
    }
  }

}
