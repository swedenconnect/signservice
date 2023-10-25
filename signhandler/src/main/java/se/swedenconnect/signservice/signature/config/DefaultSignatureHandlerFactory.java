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
package se.swedenconnect.signservice.signature.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.impl.DefaultSignatureHandler;
import se.swedenconnect.signservice.signature.signer.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.AbstractTBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.PDFTBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.XMLTBSDataProcessor;

/**
 * Factory for creating {@link DefaultSignatureHandler} handlers.
 */
public class DefaultSignatureHandlerFactory extends AbstractHandlerFactory<SignatureHandler> {

  /** {@inheritDoc} */
  @Override
  protected SignatureHandler createHandler(
      @Nullable final HandlerConfiguration<SignatureHandler> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (configuration == null) {
      return new DefaultSignatureHandler(List.of(
        this.createTbsDataProcessor(TBSDataProcessorConfiguration.XML_TYPE, null),
        this.createTbsDataProcessor(TBSDataProcessorConfiguration.PDF_TYPE, null)));
    }
    else {
      if (!DefaultSignatureHandlerConfiguration.class.isInstance(configuration)) {
        throw new IllegalArgumentException(
            "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
      }
      final DefaultSignatureHandlerConfiguration conf = DefaultSignatureHandlerConfiguration.class.cast(configuration);
      final AlgorithmRegistry algorithmRegistry = Optional.ofNullable(conf.getAlgorithmRegistry())
          .orElseGet(AlgorithmRegistrySingleton::getInstance);
      final SignServiceSignerProvider signerProvider = Optional.ofNullable(conf.getSignerProvider())
          .orElseGet(() -> new DefaultSignServiceSignerProvider(algorithmRegistry));

      final List<TBSDataProcessor> processors = new ArrayList<>();
      if (CollectionUtils.isEmpty(conf.getTbsProcessors())) {
        processors.add(this.createTbsDataProcessor(TBSDataProcessorConfiguration.XML_TYPE, null));
        processors.add(this.createTbsDataProcessor(TBSDataProcessorConfiguration.PDF_TYPE, null));
      }
      else {
        for (final TBSDataProcessorConfiguration c : conf.getTbsProcessors()) {
          if (StringUtils.isBlank(c.getType())) {
            throw new IllegalArgumentException("Missing type parameter");
          }

          AbstractTBSDataProcessor processor = null;
          if (TBSDataProcessorConfiguration.XML_TYPE.equalsIgnoreCase(c.getType())) {
            processor = this.createTbsDataProcessor(TBSDataProcessorConfiguration.XML_TYPE ,c.getSupportedProcessingRules());
            if (StringUtils.isNotBlank(c.getDefaultCanonicalizationAlgorithm())) {
              ((XMLTBSDataProcessor) processor).setDefaultCanonicalizationAlgorithm(c.getDefaultCanonicalizationAlgorithm());
            }
          }
          else if (TBSDataProcessorConfiguration.PDF_TYPE.equalsIgnoreCase(c.getType())) {
            processor = this.createTbsDataProcessor(TBSDataProcessorConfiguration.PDF_TYPE, c.getSupportedProcessingRules());
          }
          else {
            throw new IllegalArgumentException("Unsupported type: " + c.getType());
          }
          processor.setStrictProcessing(Optional.ofNullable(c.getStrictProcessing()).orElse(false));
          processor.setIncludeIssuerSerial(Optional.ofNullable(c.getIncludeIssuerSerial()).orElse(false));

          final Class<?> clazz = processor.getClass();
          if (processors.stream().anyMatch(p -> p.getClass().equals(clazz))) {
            throw new IllegalArgumentException(
                String.format("Several %s instances configured - not allowed", clazz.getSimpleName()));
          }
          processors.add(processor);
        }
      }

      return new DefaultSignatureHandler(processors, algorithmRegistry, signerProvider);
    }
  }

  /**
   * Create a new TBS data processor with global configuration settings for time skew and max message time
   *
   * @param type the type of TBS data processor being created
   * @param supportedProcessingRules supported processing rules if present or null for no processing rules
   * @return {@link AbstractTBSDataProcessor} with global configuration settings
   */
  private AbstractTBSDataProcessor createTbsDataProcessor(@Nonnull final String type, @Nullable final List<String> supportedProcessingRules) {
    Objects.requireNonNull(type, "Type must not be null");
    final AbstractTBSDataProcessor tbsDataProcessor;
    switch (type) {
    case TBSDataProcessorConfiguration.XML_TYPE:
      tbsDataProcessor = supportedProcessingRules == null
       ? new XMLTBSDataProcessor()
       : new XMLTBSDataProcessor(supportedProcessingRules);
      break;
    case TBSDataProcessorConfiguration.PDF_TYPE:
      tbsDataProcessor = supportedProcessingRules == null
        ? new PDFTBSDataProcessor()
        : new PDFTBSDataProcessor(supportedProcessingRules);
      break;
    default:
      throw new IllegalArgumentException("Unsupported TBS data processor type");
    }
    tbsDataProcessor.setAllowedClockSkew(this.getValidationConfig().getAllowedClockSkew());
    tbsDataProcessor.setMaxMessageAge(this.getValidationConfig().getMaxMessageAge());
    return tbsDataProcessor;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected Class<SignatureHandler> getHandlerType() {
    return SignatureHandler.class;
  }

}
