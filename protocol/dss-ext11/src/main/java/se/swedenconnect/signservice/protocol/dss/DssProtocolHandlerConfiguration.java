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

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolHandler;

/**
 * Handler configuration for creating {@link DssProtocolHandler} instances.
 */
public class DssProtocolHandlerConfiguration extends AbstractHandlerConfiguration<ProtocolHandler> {

  /**
   * Setting that tells whether SAML assertions should be included in the response messages. The default is to include
   * assertions.
   */
  private Boolean includeAssertion;

  /**
   * Setting that tells whether to include the request message in the response messages created. For 1.1 version and
   * below this will always be included, but in greater versions the field is optional (actually the specs dissuade from
   * using it). The default is not no include the request in responses.
   */
  private Boolean includeRequestMessage;

  /**
   * Gets the setting that tells whether SAML assertions should be included in the response messages.
   *
   * @return whether to include SAML assertions
   */
  public boolean isIncludeAssertion() {
    return this.includeAssertion != null ? this.includeAssertion : true;
  }

  /**
   * Assigns the setting that tells whether SAML assertions should be included in the response messages.
   *
   * @param includeAssertion whether to include SAML assertions
   */
  public void setIncludeAssertion(final boolean includeAssertion) {
    this.includeAssertion = includeAssertion;
  }

  /**
   * Gets the setting that tells whether to include the request message in the response messages created.
   *
   * @return whether to include the request message in the response messages created
   */
  public boolean isIncludeRequestMessage() {
    return this.includeRequestMessage != null ? this.includeRequestMessage : false;
  }

  /**
   * Assigns the setting that tells whether to include the request message in the response messages created. For 1.1
   * version and below this will always be included, but in greater versions the field is optional (actually the specs
   * dissuade from using it). The default is not no include the request in responses.
   *
   * @param includeRequestMessage whether to include the request message in the response messages created
   */
  public void setIncludeRequestMessage(final boolean includeRequestMessage) {
    this.includeRequestMessage = includeRequestMessage;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return DssProtocolHandlerFactory.class.getName();
  }

}
