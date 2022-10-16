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
package se.swedenconnect.signservice.certificate.base.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;

/**
 * Abstract base class for configuration of {@link KeyAndCertificateHandler} objects.
 */
public abstract class AbstractKeyAndCertificateHandlerConfiguration
    extends AbstractHandlerConfiguration<KeyAndCertificateHandler> {

  /**
   * Algorithm registry providing information about supported algorithms. If not assigned
   * {@link AlgorithmRegistrySingleton#getInstance()} will be used.
   */
  @Getter
  @Setter
  private AlgorithmRegistry algorithmRegistry;

  /**
   * A map specifying the key type for each supported algorithm type (primary EC and RSA algorithm types).
   * See {@link KeyGenType} for possible values. If not assigned, default key types for EC and RSA will be
   * assigned by the handler.
   */
  @Getter
  @Setter
  private Map<String, String> algorithmKeyType;

  /**
   * Configuration the user credentials container (for key generation).
   * <p>
   * Mutually exclusive with {@link keyProviderRef}.
   * </p>
   */
  @Getter
  @Setter
  private CredentialContainerConfiguration keyProvider;

  /**
   * A reference to a {@link PkiCredentialContainer} bean that is to be used for user key generation. The reason that it
   * is wise to define this a stand-alone bean is that it makes it easier to schedule tasks that periodically invoked
   * the {@link PkiCredentialContainer#cleanup()} method. This ensures that no expired credentials remain in the
   * container too long.
   * <p>
   * Mutually exclusive with {@link keyProvider}.
   * </p>
   */
  @Getter
  @Setter
  private String keyProviderRef;

  /**
   * The attribute mapper.
   */
  @Getter
  @Setter
  private AttributeMapper attributeMapper;

  /**
   * If {@code attributeMapper} is not assigned, a {@link DefaultAttributeMapper} will be created based on the
   * DefaultValuePolicyCheckerConfiguration.
   */
  @Getter
  @Setter
  private DefaultValuePolicyCheckerConfiguration defaultValuePolicyChecker;

  /**
   * The type of certificates that the CA issues.
   */
  @Getter
  @Setter
  private List<CertificateType> caSupportedCertificateTypes;

  /**
   * Certificate issuance profile configuration.
   */
  @Getter
  @Setter
  private CertificateProfileConfiguration profileConfiguration;

  /**
   * Service name placed in AuthnContextExtensions. If not set, the client ID will be used by default.
   */
  @Getter
  @Setter
  private String serviceName;

  // Internal
  private List<Class<?>> excludeFromRecursiveMergeCache = null;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected List<Class<?>> excludeFromRecursiveMerge() {
    if (this.excludeFromRecursiveMergeCache == null) {
      final List<Class<?>> list = new ArrayList<>(super.excludeFromRecursiveMerge());
      list.addAll(List.of(AlgorithmRegistry.class, AttributeMapper.class));
      this.excludeFromRecursiveMergeCache = list;
    }
    return this.excludeFromRecursiveMergeCache;
  }

  /**
   * For configuration of a {@link DefaultValuePolicyCheckerImpl} that is used to set up an attribute mapper.
   */
  @Data
  public static class DefaultValuePolicyCheckerConfiguration {

    /**
     * Configuration data for the default value policy checker.
     */
    private List<DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig> rules;

    /**
     * If no configuration exists for a supplied item (attribute type and reference), we reply with a default (true or
     * false). The default is false.
     */
    private Boolean defaultReply;
  }

}
