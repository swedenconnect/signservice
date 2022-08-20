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

import java.util.List;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultSAMLAttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultValuePolicyCheckerImpl;
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
   * Configuration for an RSA key provider.
   */
  @Getter
  @Setter
  private RsaProviderConfiguration rsaProvider;

  /**
   * Configuration for an EC key provider.
   */
  @Getter
  @Setter
  private ECProviderConfiguration ecProvider;

  /**
   * The attribute mapper.
   */
  @Getter
  @Setter
  private AttributeMapper attributeMapper;

  /**
   * If {@code attributeMapper} is not assigned, a {@link DefaultSAMLAttributeMapper} will be created based on the
   * DefaultValuePolicyCheckerConfiguration.
   */
  @Getter
  @Setter
  private DefaultValuePolicyCheckerConfiguration defaultValuePolicyChecker;

  /**
   * The certificate type to use if none has been specified in the request.
   */
  @Getter
  @Setter
  private CertificateType defaultCertificateType;

  /**
   * The default certificate profile to use.
   */
  @Getter
  @Setter
  private String defaultCertificateProfile;

  /**
   * Service name placed in AuthnContextExtensions.
   */
  @Getter
  @Setter
  private String serviceName;

  /**
   * For configuration of a {@link DefaultValuePolicyCheckerImpl} that is used to set up an attribute mapper.
   */
  @Data
  public static class DefaultValuePolicyCheckerConfiguration {

    /**
     * Configuration data for the default value policy checker.
     */
    private List<DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig> c;

    /**
     * If no configuration exists for a supplied item (attribute type and reference), we reply with a default (true or
     * false). The default is false.
     */
    private boolean defaultReply = false;
  }

  /**
   * Configuration for an RSA key provider.
   */
  @Data
  public static class RsaProviderConfiguration {

    /**
     * The keysize in bits.
     */
    private int keySize;

    /**
     * The number of keys stored in this key stack. If not set, RSA keys will be generated on demand.
     */
    private Integer stackSize;
  }

  /**
   * Configuration for an EC key provider.
   */
  @Data
  public static class ECProviderConfiguration {

    /**
     * The name of the EC curve for the EC provider.
     */
    private String curveName;
  }

}
