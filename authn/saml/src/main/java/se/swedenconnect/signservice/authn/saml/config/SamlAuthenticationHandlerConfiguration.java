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
package se.swedenconnect.signservice.authn.saml.config;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.storage.MessageReplayChecker;

/**
 * Base class for configuring SAML authentication handlers.
 */
public class SamlAuthenticationHandlerConfiguration
    extends AbstractHandlerConfiguration<AuthenticationHandler> {

  /** The default SAML type. */
  public static final String SAML_TYPE_DEFAULT = "default";

  /** The SAML type for the Sweden Connect federation. */
  public static final String SAML_TYPE_SWEDEN_CONNECT = "sweden-connect";

  /**
   * The type of SAML "dialect" used. If not set, {@value #SAML_TYPE_DEFAULT} is used.
   */
  @Setter
  @Getter
  private String samlType = SAML_TYPE_DEFAULT;

  /**
   * The SAML entityID.
   */
  @Setter
  @Getter
  private String entityId;

  /**
   * The SAML SP default credential. Used if no specific credential is given for signing and/or encrypt/decrypt.
   */
  @Setter
  @Getter
  private PkiCredential defaultCredential;

  /**
   * The SAML SP signature credential.
   */
  @Setter
  @Getter
  private PkiCredential signatureCredential;

  /**
   * The SAML SP decryption credential.
   */
  @Setter
  @Getter
  private PkiCredential decryptionCredential;

  /**
   * Configuration for the SAML SP paths.
   */
  @Setter
  @Getter
  private SpUrlConfiguration spPaths;

  /**
   * A list of metadata providers.
   */
  @Setter
  @Getter
  private List<MetadataProviderConfiguration> metadataProviders;

  /**
   * The SAML SP metadata.
   */
  @Setter
  @Getter
  private MetadataConfiguration metadata;

  /**
   * The message replay checker.
   */
  @Setter
  @Getter
  private MessageReplayChecker messageReplayChecker;

  /**
   * Whether AuthnRequest messages should be signed by the SP.
   */
  @Setter
  @Getter
  private boolean signAuthnRequests = true;

  /**
   * Whether encrypted assertions are required.
   */
  @Setter
  @Getter
  private boolean requireEncryptedAssertions = true;

  /**
   * Response validation settings.
   */
  @Setter
  @Getter
  private ResponseValidationSettings responseValidation;

  // Internal
  private List<Class<?>> excludeFromRecursiveMergeCache = null;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return SamlAuthenticationHandlerFactory.class.getName();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected List<Class<?>> excludeFromRecursiveMerge() {
    if (this.excludeFromRecursiveMergeCache == null) {
      final List<Class<?>> list = new ArrayList<>(super.excludeFromRecursiveMerge());
      list.addAll(List.of(MessageReplayChecker.class, EntityDescriptor.class));
      this.excludeFromRecursiveMergeCache = list;
    }
    return this.excludeFromRecursiveMergeCache;
  }

}
