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
import se.swedenconnect.signservice.signature.signer.SignServiceSigner;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessorProvider;

import java.security.SignatureException;
import java.util.Optional;

/**
 * Default implementation of the {@link SignatureHandler} interface.
 */
public class DefaultSignatureHandler implements SignatureHandler {

  /** sign service signer provider */
  private final SignServiceSignerProvider signServiceSignerProvider;

  /** To be signed data processor provider */
  private final TBSDataProcessorProvider tbsDataProcessorProvider;

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
  public DefaultSignatureHandler(final AlgorithmRegistry algorithmRegistry,
    TBSDataProcessorProvider tbsDataProcessorProvider) {
    this.signServiceSignerProvider = new DefaultSignServiceSignerProvider(algorithmRegistry);
    this.algorithmRegistry = algorithmRegistry;
    this.tbsDataProcessorProvider = tbsDataProcessorProvider;
  }

  /**
   * Constructor
   *
   * @param algorithmRegistry algorithm registry
   * @param signServiceSignerProvider sign service signer provider
   */
  public DefaultSignatureHandler(final AlgorithmRegistry algorithmRegistry,
    final SignServiceSignerProvider signServiceSignerProvider, TBSDataProcessorProvider tbsDataProcessorProvider) {
    this.signServiceSignerProvider = signServiceSignerProvider;
    this.algorithmRegistry = algorithmRegistry;
    this.tbsDataProcessorProvider = tbsDataProcessorProvider;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return Optional.ofNullable(this.name).orElse(this.getClass().getSimpleName());
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(final SignRequestMessage signRequest, final SignServiceContext context)
    throws InvalidRequestException {

    // TODO: Implement

    // TODO: Check if algorithm is both known and supported (not deprecated)

  }

  /** {@inheritDoc} */
  @Override
  public CompletedSignatureTask sign(final RequestedSignatureTask signatureTask, final PkiCredential signingCredential,
    final SignRequestMessage signRequest, final SignServiceContext context) throws SignatureException {

    try {
      SignatureType signatureType = signatureTask.getSignatureType();
      String signatureAlgorithmUri = signRequest.getSignatureRequirements().getSignatureAlgorithm();
      SignServiceSigner signer = signServiceSignerProvider.getSigner(signatureAlgorithmUri, signatureType);

      SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(
        signatureAlgorithmUri);

      TBSDataProcessor tbsDataProcessor = tbsDataProcessorProvider.getTBSDataProcessor(signatureAlgorithm);
      TBSProcessingData tbsProcessingData = tbsDataProcessor.getTBSData(signatureTask, signingCredential, signatureAlgorithm);

      byte[] signature = signer.sign(tbsProcessingData.getTBSBytes(), signingCredential.getPrivateKey(), signatureAlgorithm);
      DefaultCompletedSignatureTask completedSignatureTask = new DefaultCompletedSignatureTask(signatureTask);
      completedSignatureTask.setSignature(signature);
      completedSignatureTask.setSignatureAlgorithmUri(signatureAlgorithmUri);
      completedSignatureTask.setTbsData(tbsProcessingData.getTBSBytes());
      completedSignatureTask.setAdESObject(tbsProcessingData.getAdESObject());
      completedSignatureTask.setProcessingRulesUri(tbsProcessingData.getProcessingRules());

      return completedSignatureTask;

    }
    catch (Exception e) {
      throw new SignatureException("Failed to sign the requested data", e);
    }
  }

}
