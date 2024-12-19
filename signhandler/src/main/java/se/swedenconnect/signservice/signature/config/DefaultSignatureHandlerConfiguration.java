/*
 * Copyright 2022-2024 Sweden Connect
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

import java.util.List;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.impl.DefaultSignatureHandler;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;

/**
 * Configuration class for {@link DefaultSignatureHandler}.
 */
public class DefaultSignatureHandlerConfiguration extends AbstractHandlerConfiguration<SignatureHandler> {

  /**
   * The algorithm registry. If not assigned, the registry given from a call to {@link AlgorithmRegistrySingleton#getInstance()} will be used.
   */
  @Setter
  @Getter
  @Nullable
  private AlgorithmRegistry algorithmRegistry;

  /**
   * The signer provider. If not assigned, DefaultSignServiceSignerProvider will be used.
   */
  @Setter
  @Getter
  @Nullable
  private SignServiceSignerProvider signerProvider;

  /**
   * TBS processors. If not assigned, an XML and a PDF processor are created using default settings.
   */
  @Setter
  @Getter
  @Nullable
  private List<TBSDataProcessorConfiguration> tbsProcessors;


  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return DefaultSignatureHandlerFactory.class.getName();
  }

}
