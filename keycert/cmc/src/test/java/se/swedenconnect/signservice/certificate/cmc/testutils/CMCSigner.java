/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate.cmc.testutils;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

/**
 * CMC data signer
 */
public class CMCSigner {

  private final KeyPair signerKeyPair;
  private final List<X509Certificate> signerCertChain;
  private final boolean pss;
  private ContentSigner contentSigner;

  public CMCSigner(KeyPair signerKeyPair, X509Certificate signerCert, boolean pss)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    this.signerKeyPair = signerKeyPair;
    this.signerCertChain = Arrays.asList(signerCert);
    this.pss = pss;
    setContentSigner();
  }

  public CMCSigner(KeyPair signerKeyPair, X509Certificate signerCert)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    this.signerKeyPair = signerKeyPair;
    this.signerCertChain = Arrays.asList(signerCert);
    this.pss = false;
    setContentSigner();
  }

  private void setContentSigner() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    PublicKey publicKey = signerKeyPair.getPublic();
    String algo = null;
    if (publicKey instanceof RSAPublicKey) {
      if (pss) {
        algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
      } else {
        algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256;
      }
    } else {
      algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;
    }
    contentSigner = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algo)).build(signerKeyPair.getPrivate());
  }

  public ContentSigner getContentSigner() {
    return contentSigner;
  }

  public List<X509Certificate> getSignerChain() {
    return signerCertChain;
  }
}
