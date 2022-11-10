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

import java.security.SignatureException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signer.SignServiceSigner;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

/**
 * Default implementation of the {@link SignatureHandler} interface.
 */
@Slf4j
public class DefaultSignatureHandler extends AbstractSignServiceHandler implements SignatureHandler {

  /** sign service signer provider */
  private final SignServiceSignerProvider signServiceSignerProvider;

  /** Algorithm registry */
  private final AlgorithmRegistry algorithmRegistry;

  /** The TBS data processors. */
  private List<TBSDataProcessor> tbsDataProcessors;

  /**
   * Constructor assigning the {@link TBSDataProcessor} instances to use. A default algorithm registry
   * ({@link AlgorithmRegistrySingleton#getInstance()}) and signer provider ({@link DefaultSignServiceSignerProvider})
   * is used.
   *
   * @param tbsDataProcessors a list of TBS data processors
   */
  public DefaultSignatureHandler(@Nonnull final List<TBSDataProcessor> tbsDataProcessors) {
    this(tbsDataProcessors, null, null);
  }

  /**
   * Constructor assigning the {@link TBSDataProcessor} instances to use and an algorithm registry. A default signer
   * provider ({@link DefaultSignServiceSignerProvider}) is used.
   *
   * @param tbsDataProcessors a list of TBS data processors
   * @param algorithmRegistry algorithm registry
   */
  public DefaultSignatureHandler(
      @Nonnull final List<TBSDataProcessor> tbsDataProcessors,
      @Nullable final AlgorithmRegistry algorithmRegistry) {
    this(tbsDataProcessors, algorithmRegistry, null);
  }

  /**
   * Constructor.
   * <p>
   * If {@code algorithmRegistry} is {@code null}, a default algorithm registry
   * ({@link AlgorithmRegistrySingleton#getInstance()}) is used. If {@code signServiceSignerProvider} is {@code null} a
   * default signer provider ({@link DefaultSignServiceSignerProvider}) is used.
   * </p>
   *
   * @param tbsDataProcessors a list of TBS data processors
   * @param algorithmRegistry algorithm registry
   * @param signServiceSignerProvider sign service signer provider
   */
  public DefaultSignatureHandler(
      @Nonnull final List<TBSDataProcessor> tbsDataProcessors,
      @Nullable final AlgorithmRegistry algorithmRegistry,
      @Nullable final SignServiceSignerProvider signServiceSignerProvider) {
    this.tbsDataProcessors = Objects.requireNonNull(tbsDataProcessors, "tbsDataProcessors must not be null");
    this.algorithmRegistry = Optional.ofNullable(algorithmRegistry)
        .orElseGet(() -> AlgorithmRegistrySingleton.getInstance());
    this.signServiceSignerProvider = Optional.ofNullable(signServiceSignerProvider)
        .orElseGet(() -> new DefaultSignServiceSignerProvider(this.algorithmRegistry));

    if (this.tbsDataProcessors.isEmpty()) {
      throw new IllegalArgumentException("tbsDataProcessors must not be empty");
    }
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws InvalidRequestException {

    log.debug("Checking signature process requirements on sign request input");

    Objects.requireNonNull(signRequest, "signRequest must not be null");

    // Check signature algorithm
    final SignatureRequirements signatureRequirements = Optional.ofNullable(signRequest.getSignatureRequirements())
        .orElseThrow(() -> new InvalidRequestException("Signature requirements must be present"));

    final String sigAlgorithmUri = Optional.ofNullable(signatureRequirements.getSignatureAlgorithm())
        .orElseThrow(() -> new InvalidRequestException("Signature algorithm in request must not be null"));

    final Algorithm algorithm = Optional.ofNullable(this.algorithmRegistry.getAlgorithm(sigAlgorithmUri))
        .orElseThrow(() -> new InvalidRequestException("Signature algorithm is not in the algorithm registry"));
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new InvalidRequestException("Requested algorithm is not a signature algorithm");
    }

    final SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) algorithm;
    if (signatureAlgorithm.isBlacklisted()) {
      throw new InvalidRequestException("Specified signature algorithm is blacklisted");
    }
    log.debug("Signature algorithm {} is supported for signing", sigAlgorithmUri);

    // Check sign task data
    if (signRequest.getSignatureTasks() == null || signRequest.getSignatureTasks().isEmpty()) {
      throw new InvalidRequestException("No sign tasks are available");
    }
    log.debug("Found {} sign task(s) to process", signRequest.getSignatureTasks().size());
    for (final RequestedSignatureTask signTask : signRequest.getSignatureTasks()) {
      try {
        this.getTBSDataProcessor(signTask.getSignatureType()).checkSignTask(signTask, signatureAlgorithm);
      }
      catch (final SignatureException e) {
        throw new InvalidRequestException(e.getMessage(), e);
      }
    }
    log.debug("All sign tasks pass all compliance checks");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public CompletedSignatureTask sign(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final PkiCredential signingCredential,
      @Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws SignatureException {
    log.debug("Starting process to sign data");

    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signingCredential, "Signing credentials must not be null");
    Objects.requireNonNull(signRequest, "SignRequest must not be null");

    final SignatureType signatureType = signatureTask.getSignatureType();
    log.debug("Requested signature type: {}", signatureType);

    try {
      // Check the requirements on the sign request data
      this.checkRequirements(signRequest, context);
    }
    catch (final InvalidRequestException e) {
      throw new SignatureException(e.getMessage(), e);
    }

    final String signatureAlgorithmUri = signRequest.getSignatureRequirements().getSignatureAlgorithm();
    final SignatureAlgorithm signatureAlgorithm =
        (SignatureAlgorithm) this.algorithmRegistry.getAlgorithm(signatureAlgorithmUri);
    log.debug("Signature algorithm: {}", signatureAlgorithm.getJcaName());

    final SignServiceSigner signer = this.signServiceSignerProvider.getSigner(signatureAlgorithmUri, signatureType);
    log.debug("Obtained signer of class {}", signer.getClass().getSimpleName());

    final TBSDataProcessor tbsDataProcessor = this.getTBSDataProcessor(signatureType);
    log.debug("Obtained TBS data processor of type: {}", tbsDataProcessor.getClass().getSimpleName());
    final TBSProcessingData tbsProcessingData = tbsDataProcessor.processSignTaskData(signatureTask,
        signingCredential.getCertificate(),
        signatureAlgorithm);

    final byte[] signature = signer.sign(tbsProcessingData.getTBSBytes(), signingCredential.getPrivateKey(),
        signatureAlgorithm);
    final DefaultCompletedSignatureTask completedSignatureTask = new DefaultCompletedSignatureTask(signatureTask);
    completedSignatureTask.setSignature(signature);
    completedSignatureTask.setSignatureAlgorithmUri(signatureAlgorithmUri);
    completedSignatureTask.setTbsData(tbsProcessingData.getTBSBytes());
    completedSignatureTask.setAdESObject(tbsProcessingData.getAdESObject());
    completedSignatureTask.setProcessingRulesUri(tbsProcessingData.getProcessingRules());
    log.debug("Sign task completed");

    return completedSignatureTask;
  }

  /**
   * Gets the {@link TBSDataProcessor} that supports the given signature type.
   *
   * @param signatureType the signature type
   * @return a TBSDataProcessor
   * @throws SignatureException if no matching processor is found
   */
  private TBSDataProcessor getTBSDataProcessor(@Nonnull final SignatureType signatureType) throws SignatureException {
    return this.tbsDataProcessors.stream()
        .filter(p -> p.supportsType(signatureType))
        .findFirst()
        .orElseThrow(() -> new SignatureException("Signature type " + signatureType + " is not supported"));
  }

}
