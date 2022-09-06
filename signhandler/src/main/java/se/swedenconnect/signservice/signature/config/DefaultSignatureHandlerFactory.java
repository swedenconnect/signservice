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
package se.swedenconnect.signservice.signature.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.annotation.Nullable;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.impl.DefaultSignatureHandler;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.impl.AbstractTBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.impl.PDFTBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.impl.XMLTBSDataProcessor;

/**
 * Factory for creating {@link DefaultSignatureHandler} handlers.
 */
public class DefaultSignatureHandlerFactory extends AbstractHandlerFactory<SignatureHandler> {

  /** {@inheritDoc} */
  @Override
  protected SignatureHandler createHandler(@Nullable final HandlerConfiguration<SignatureHandler> configuration)
      throws IllegalArgumentException {

    if (configuration == null) {
      return new DefaultSignatureHandler(Arrays.asList(
          new XMLTBSDataProcessor(), new PDFTBSDataProcessor()));
    }
    else {
      if (!DefaultSignatureHandlerConfiguration.class.isInstance(configuration)) {
        throw new IllegalArgumentException(
            "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
      }
      final DefaultSignatureHandlerConfiguration conf = DefaultSignatureHandlerConfiguration.class.cast(configuration);
      final AlgorithmRegistry algorithmRegistry = Optional.ofNullable(conf.getAlgorithmRegistry())
          .orElseGet(() -> AlgorithmRegistrySingleton.getInstance());
      final SignServiceSignerProvider signerProvider = Optional.ofNullable(conf.getSignerProvider())
          .orElseGet(() -> new DefaultSignServiceSignerProvider(algorithmRegistry));

      final List<TBSDataProcessor> processors = new ArrayList<>();
      if (CollectionUtils.isEmpty(conf.getTbsProcessors())) {
        processors.add(new XMLTBSDataProcessor());
        processors.add(new PDFTBSDataProcessor());
      }
      else {
        for (final TBSDataProcessorConfiguration c : conf.getTbsProcessors()) {
          if (StringUtils.isBlank(c.getType())) {
            throw new IllegalArgumentException("Missing type parameter");
          }

          AbstractTBSDataProcessor processor = null;
          if ("xml".equalsIgnoreCase(c.getType())) {
            processor = new XMLTBSDataProcessor(c.getSupportedProcessingRules());
            if (StringUtils.isNotBlank(c.getDefaultCanonicalizationAlgorithm())) {
              ((XMLTBSDataProcessor) processor).setDefaultCanonicalizationAlgorithm(c.getDefaultCanonicalizationAlgorithm());
            }
          }
          else if ("pdf".equalsIgnoreCase(c.getType())) {
            processor = new PDFTBSDataProcessor(c.getSupportedProcessingRules());
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


}
