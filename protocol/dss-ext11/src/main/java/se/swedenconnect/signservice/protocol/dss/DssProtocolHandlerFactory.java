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
package se.swedenconnect.signservice.protocol.dss;

import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolHandler;

/**
 * A handler factory for creating {@link DssProtocolHandler} instances.
 */
public class DssProtocolHandlerFactory extends AbstractHandlerFactory<ProtocolHandler> {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected ProtocolHandler createHandler(@Nullable final HandlerConfiguration<ProtocolHandler> configuration)
      throws IllegalArgumentException {

    if (configuration != null) {
      if (!DssProtocolHandlerConfiguration.class.isInstance(configuration)) {
        throw new IllegalArgumentException(
            "Unsupported protocol handler configuration class: " + configuration.getClass().getName());
      }
    }
    final DssProtocolHandlerConfiguration conf = Optional.ofNullable(configuration)
        .map(DssProtocolHandlerConfiguration.class::cast)
        .orElseGet(() -> new DssProtocolHandlerConfiguration());

    final DssProtocolHandler handler = new DssProtocolHandler();
    final DssSignResponseMessage.ResponseConfiguration responseConfig =
        new DssSignResponseMessage.ResponseConfiguration();

    handler.setName(conf.getName());
    responseConfig.includeAssertion = conf.isIncludeAssertion();
    responseConfig.includeRequestMessage = conf.isIncludeRequestMessage();
    handler.setResponseConfiguration(responseConfig);

    return handler;
  }

}
