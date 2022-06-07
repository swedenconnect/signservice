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
package se.swedenconnect.signservice.signature.impl;

import lombok.Setter;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSigner;
import se.swedenconnect.signservice.signature.signhandler.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signhandler.impl.DefaultSignServiceSignerProvider;

import java.security.SignatureException;
import java.util.Optional;

/**
 * Default implementation of the {@link SignatureHandler} interface.
 */
public class DefaultSignatureHandler implements SignatureHandler {

  /** Default name of this handler. */
  public static final String DEFAULT_NAME = "DefaultSignatureHandler";

  /** sign service signer provider */
  private final SignServiceSignerProvider signServiceSignerProvider;

  /** Algorithm registry */
  private final AlgorithmRegistry algorithmRegistry;

  /**
   * The name of this handler.
   *
   * @param name the handler name
   */
  @Setter
  private String name;

  /**
   * Constructor with default sign service signer provider
   *
   * @param algorithmRegistry algorithm registry
   */
  public DefaultSignatureHandler(final AlgorithmRegistry algorithmRegistry) {
    this.signServiceSignerProvider = new DefaultSignServiceSignerProvider(algorithmRegistry);
    this.algorithmRegistry = algorithmRegistry;
  }

  /**
   * Constructor
   *
   * @param algorithmRegistry algorithm registry
   * @param signServiceSignerProvider sign service signer provider
   */
  public DefaultSignatureHandler(final AlgorithmRegistry algorithmRegistry,
    final SignServiceSignerProvider signServiceSignerProvider) {
    this.signServiceSignerProvider = signServiceSignerProvider;
    this.algorithmRegistry = algorithmRegistry;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return Optional.ofNullable(this.name).orElse(DEFAULT_NAME);
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(final SignRequestMessage signRequest, final SignServiceContext context)
    throws InvalidRequestException {

    // TODO: Implement

  }

  /** {@inheritDoc} */
  @Override
  public CompletedSignatureTask sign(final RequestedSignatureTask signatureTask, final PkiCredential signingCredential,
    final SignRequestMessage signRequest, final SignServiceContext context) throws SignatureException {

    try {
      SignatureType signatureType = signatureTask.getSignatureType();
      String signatureAlgorithmUri = signRequest.getSignatureRequirements().getSignatureAlgorithm();
      SignServiceSigner signer = signServiceSignerProvider.getSigner(signatureAlgorithmUri, signatureType);

      SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(signatureAlgorithmUri);

      // TODO prepare data to be signed and use the signer to sign

      byte[] signature = signer.sign(null, signingCredential.getPrivateKey(), signatureAlgorithm);
      DefaultCompletedSignatureTask completedSignatureTask = new DefaultCompletedSignatureTask(signatureTask);
      completedSignatureTask.setSignature(signature);
      completedSignatureTask.setSignatureAlgorithmUri(signatureAlgorithmUri);

    }
    catch (Exception ex) {
      // TODO handle exceptions
    }

    // TODO: Implement
    return null;
  }

}
