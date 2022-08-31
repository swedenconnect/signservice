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
package se.swedenconnect.signservice.certificate.base.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Utilities for tests
 */
public class TestUtils {

  public static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }

  public static X509Certificate generateCertificate(PkiCredential pair, X500Name subjectDN, String algorithmJcaName)
      throws OperatorCreationException, IOException, CertificateException, KeyStoreException {
    BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
    Calendar startTime = Calendar.getInstance();
    startTime.setTime(new Date());
    startTime.add(10, -2);
    Calendar expiryTime = Calendar.getInstance();
    expiryTime.setTime(new Date());
    expiryTime.add(1, 5);
    Date notBefore = startTime.getTime();
    Date notAfter = expiryTime.getTime();
    PublicKey pubKey = pair.getPublicKey();
    JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(subjectDN, certSerial, notBefore, notAfter,
        subjectDN, pubKey);
    ContentSigner signer = (new JcaContentSignerBuilder(algorithmJcaName)).build(pair.getPrivateKey());
    byte[] encoded = certGen.build(signer).getEncoded();
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    try (InputStream is = new ByteArrayInputStream(encoded)) {
      X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
      return certificate;
    }

  }

  public static X500Name getDn(Map<X509DnNameType, String> nameMap) {
    Set<X509DnNameType> keySet = nameMap.keySet();
    RDN[] rdnArray = new RDN[keySet.size()];
    int i = 0;

    AttributeTypeAndValue atav;
    for (Iterator<?> var5 = keySet.iterator(); var5.hasNext(); rdnArray[i++] = new RDN(atav)) {
      X509DnNameType nt = (X509DnNameType) var5.next();
      String value = nameMap.get(nt);
      atav = nt.getAttribute(value);
    }

    X500Name dn = new X500Name(rdnArray);
    return dn;
  }

  public static class DNBuilder {

    Map<X509DnNameType, String> nameMap;

    public static DNBuilder getInstance() {
      return new DNBuilder();
    }

    public DNBuilder() {
      nameMap = new HashMap<>();
    }

    public DNBuilder attr(X509DnNameType attr, String val) {
      nameMap.put(attr, val);
      return this;
    }

    public int getSize() {
      return nameMap.size();
    }

    public X500Name build() {
      return getDn(nameMap);
    }
  }

}
