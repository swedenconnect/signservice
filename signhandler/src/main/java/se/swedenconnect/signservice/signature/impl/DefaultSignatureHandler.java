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
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signer.SignServiceSigner;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessorProvider;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;
import se.swedenconnect.signservice.signature.tbsdata.impl.DefaultTBSDataProcessorProvider;

import javax.annotation.Nonnull;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Optional;

/**
 * Default implementation of the {@link SignatureHandler} interface.
 */
@Slf4j
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
   * Constructor with default sign service signer provider and default TBS data processor
   *
   * @param algorithmRegistry algorithm registry
   */
  public DefaultSignatureHandler(@Nonnull final AlgorithmRegistry algorithmRegistry) {
    this(algorithmRegistry, new DefaultSignServiceSignerProvider(algorithmRegistry),
      new DefaultTBSDataProcessorProvider());
  }

  /**
   * Constructor
   *
   * @param algorithmRegistry algorithm registry
   * @param signServiceSignerProvider sign service signer provider
   */
  public DefaultSignatureHandler(@Nonnull final AlgorithmRegistry algorithmRegistry,
    @Nonnull final SignServiceSignerProvider signServiceSignerProvider,
    @Nonnull final TBSDataProcessorProvider tbsDataProcessorProvider) {
    this.signServiceSignerProvider = signServiceSignerProvider;
    this.algorithmRegistry = algorithmRegistry;
    this.tbsDataProcessorProvider = tbsDataProcessorProvider;

    Objects.requireNonNull(algorithmRegistry, "Algorithm registry must not be null");
    Objects.requireNonNull(signServiceSignerProvider, "Signer provider must not be null");
    Objects.requireNonNull(tbsDataProcessorProvider, "TBS data processor must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return Optional.ofNullable(this.name).orElse(this.getClass().getSimpleName());
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(@Nonnull final SignRequestMessage signRequest, final SignServiceContext context)
    throws InvalidRequestException {

    Objects.requireNonNull(signRequest, "SignRequest must not be null");

    // Check signature algorithm
    SignatureRequirements signatureRequirements = Optional.ofNullable(signRequest.getSignatureRequirements())
      .orElseThrow(() -> new InvalidRequestException("Signature requirements must be present"));
    String sigAlgorithmUri = Optional.ofNullable(signatureRequirements.getSignatureAlgorithm())
      .orElseThrow(() -> new InvalidRequestException("Signature algorithm in request must not be null"));
    Algorithm algorithm = Optional.ofNullable(algorithmRegistry.getAlgorithm(sigAlgorithmUri))
      .orElseThrow(() -> new InvalidRequestException("Signature algorithm is not in the algorithm registry"));
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new InvalidRequestException("Requested algorithm is not a signature algorithm");
    }
    SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithm;
    if (signatureAlgorithm.isBlacklisted()) {
      throw new InvalidRequestException("Specified signature algorithm is blacklisted");
    }

    // Check sign task data
    if (signRequest.getSignatureTasks() == null || signRequest.getSignatureTasks().isEmpty()) {
      throw new InvalidRequestException("No sign tasks are available");
    }
    for (RequestedSignatureTask signTask : signRequest.getSignatureTasks()) {
      try {
        TBSDataProcessor tbsDataProcessor = tbsDataProcessorProvider.getTBSDataProcessor(signTask.getSignatureType());
        tbsDataProcessor.checkSignTask(signTask, signatureAlgorithm);
      }
      catch (SignatureException e) {
        throw new InvalidRequestException(e.getMessage());
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public CompletedSignatureTask sign(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignRequestMessage signRequest, final SignServiceContext context) throws SignatureException {
    log.debug("Starting process to sign data");

    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signingCredential, "Signing credentials must not be null");
    Objects.requireNonNull(signRequest, "SignRequest must not be null");

    SignatureType signatureType = signatureTask.getSignatureType();
    log.debug("Requested signature type: {}", signatureType);

    try {
      // Check the requirements on the sign request data
      checkRequirements(signRequest, context);
    }
    catch (InvalidRequestException e) {
      throw new SignatureException(e.getMessage());
    }

    String signatureAlgorithmUri = signRequest.getSignatureRequirements().getSignatureAlgorithm();
    SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(signatureAlgorithmUri);
    log.debug("Signature algorithm: {}", signatureAlgorithm.getJcaName());

    SignServiceSigner signer = signServiceSignerProvider.getSigner(signatureAlgorithmUri, signatureType);
    log.debug("Obtained signer of class {}", signer.getClass().getSimpleName());

    TBSDataProcessor tbsDataProcessor = tbsDataProcessorProvider.getTBSDataProcessor(signatureType);
    log.debug("Obtained TBS data processor of type: {}", tbsDataProcessor.getClass().getSimpleName());
    TBSProcessingData tbsProcessingData = tbsDataProcessor.processSignTaskData(signatureTask,
      signingCredential.getCertificate(),
      signatureAlgorithm);

    byte[] signature = signer.sign(tbsProcessingData.getTBSBytes(), signingCredential.getPrivateKey(),
      signatureAlgorithm);
    DefaultCompletedSignatureTask completedSignatureTask = new DefaultCompletedSignatureTask(signatureTask);
    completedSignatureTask.setSignature(signature);
    completedSignatureTask.setSignatureAlgorithmUri(signatureAlgorithmUri);
    completedSignatureTask.setTbsData(tbsProcessingData.getTBSBytes());
    completedSignatureTask.setAdESObject(tbsProcessingData.getAdESObject());
    completedSignatureTask.setProcessingRulesUri(tbsProcessingData.getProcessingRules());
    log.debug("Sign task completed");

    return completedSignatureTask;
  }

}
