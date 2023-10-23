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
package se.swedenconnect.signservice.authn.saml.config;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import jakarta.annotation.Nonnull;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
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
  private String samlType;

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
  private PkiCredentialConfiguration defaultCredential;

  /**
   * The SAML SP signature credential.
   */
  @Setter
  @Getter
  private PkiCredentialConfiguration signatureCredential;

  /**
   * The SAML SP decryption credential.
   */
  @Setter
  @Getter
  private PkiCredentialConfiguration decryptionCredential;

  /**
   * Configuration for the SAML SP paths.
   */
  @Setter
  @Getter
  private SpUrlConfiguration spPaths;

  /**
   * Metadata provider(s). Mutually exclusive with {@code metadataProviderRef}.
   */
  @Setter
  @Getter
  private MetadataProviderConfiguration metadataProvider;

  /**
   * A bean reference to a metadata provider {@link MetadataProvider}. Mutually exclusive with {@code metadataProvider}.
   */
  @Setter
  @Getter
  private String metadataProviderRef;

  /**
   * The SAML SP metadata.
   */
  @Setter
  @Getter
  private MetadataConfiguration metadata;

  /**
   * The message replay checker. Mutually exclusive with {@code messageReplayCheckerRef}.
   */
  @Setter
  @Getter
  private MessageReplayChecker messageReplayChecker;

  /**
   * A bean reference to a {@link MessageReplayChecker}. Mutually exclusive with {@code messageReplayChecker}.
   */
  @Setter
  @Getter
  private String messageReplayCheckerRef;

  /**
   * Whether AuthnRequest messages should be signed by the SP. The default is {@code true}.
   */
  @Setter
  @Getter
  private Boolean signAuthnRequests;

  /**
   * Whether encrypted assertions are required. The default is {@code true}.
   */
  @Setter
  @Getter
  private Boolean requireEncryptedAssertions;

  /**
   * Whether signed assertions are required. The default is {@code false}.
   */
  @Setter
  @Getter
  private Boolean requireSignedAssertions;

  /**
   * The preferred SAML binding to use when sending authenticaion requests. Possible values are "redirect" and "post".
   * The default is "redirect".
   */
  @Setter
  @Getter
  private String preferredBinding;

  /**
   * Only relevant for the Sweden Connect SAML type. Tells how the {@link SADRequest} extension should be handled.
   */
  @Setter
  @Getter
  private SadRequestRequirement sadRequest;

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

  /**
   * Enumeration that tells whether we should include the {@link SADRequest} extension. Applies only to the
   * Sweden Connect profile.
   */
  public static enum SadRequestRequirement {

    /**
     * Default behaviour - Sends a SADReequest extension if the requested certificate type is QC_SSDD and if not, does
     * not include the extension.
     */
    DEFAULT,

    /**
     * Never send SADRequest.
     */
    NEVER,

    /**
     * Always send SADRequest (if supported by the IdP).
     */
    ALWAYS;
  }

}
