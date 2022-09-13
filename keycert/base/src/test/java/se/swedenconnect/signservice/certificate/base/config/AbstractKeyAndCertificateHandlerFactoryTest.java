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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration.DefaultValuePolicyCheckerConfiguration;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration.ECProviderConfiguration;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration.RsaProviderConfiguration;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * Test cases for AbstractKeyAndCertificateHandlerFactory.
 */
public class AbstractKeyAndCertificateHandlerFactoryTest {

  @Test
  public void testCreate() {
    final TestConfig config = this.getFullConfig();
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testUseStackedRsaKeyProvider() {
    final TestConfig config = this.getFullConfig();
    config.getRsaProvider().setStackSize(1);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testOnlyRsaKeyProvider() {
    final TestConfig config = this.getFullConfig();
    config.setEcProvider(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testOnlyEcKeyProvider() {
    final TestConfig config = this.getFullConfig();
    config.setRsaProvider(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testMissingKeyProviders() {
    final TestConfig config = this.getFullConfig();
    config.setRsaProvider(null);
    config.setEcProvider(null);
    final TestFactory factory = new TestFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("At least one key provider must be supplied");
  }

  @Test
  public void testSuppliedAttributeMapper() {
    final TestConfig config = this.getFullConfig();
    final AttributeMapper attributeMapper = Mockito.mock(AttributeMapper.class);
    config.setAttributeMapper(attributeMapper);
    final TestFactory factory = new TestFactory();

    KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));

    config.setDefaultValuePolicyChecker(null);
    handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testNoDefaultValuePolicyChecker() {
    final TestConfig config = this.getFullConfig();
    config.setDefaultValuePolicyChecker(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testNoCertificateType() {
    final TestConfig config = this.getFullConfig();
    config.setCaCertificateType(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testNoHandlerName() {
    final TestConfig config = this.getFullConfig();
    config.setName(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
    Assertions.assertEquals(TestHandler.class.getSimpleName(), handler.getName());
  }

  @Test
  public void testNoServiceName() {
    final TestConfig config = this.getFullConfig();
    config.setServiceName(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testUseDefaultAlgorithmRegistry() {
    final TestConfig config = this.getFullConfig();
    config.setAlgorithmRegistry(null);
    final TestFactory factory = new TestFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(TestHandler.class.isInstance(handler));
  }

  @Test
  public void testMissingConfig() throws Exception {
    final TestFactory factory = new TestFactory();
    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration");
  }

  @Test
  public void testBadConfigType() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new HandlerConfiguration<KeyAndCertificateHandler>() {

      @Override
      public String getFactoryClass() {
        return null;
      }

      @Override
      public void setFactoryClass(String factoryClass) {
      }

      @Override
      public void setName(String name) {
      }

      @Override
      public String getName() {
        return null;
      }

      @Override
      public void setDefaultConfig(HandlerConfiguration<KeyAndCertificateHandler> defaultConfig) {
      }

      @Override
      public HandlerConfiguration<KeyAndCertificateHandler> getDefaultConfig() {
        return null;
      }

      @Override
      public void setDefaultConfigRef(String defaultConfigRef) {
      }

      @Override
      public String getDefaultConfigRef() {
        return null;
      }

      @Override
      public boolean needsDefaultConfigResolving() {
        return false;
      }

      @Override
      public void resolveDefaultConfigRef(Function<String, HandlerConfiguration<KeyAndCertificateHandler>> resolver)
          throws NullPointerException, IllegalArgumentException {
      }

      @Override
      public void setBeanName(String beanName) {
      }

      @Override
      public String getBeanName() {
        return null;
      }

      @Override
      public void init() throws Exception {
      }

    };
    final TestFactory factory = new TestFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testHandlerType() {
    final TestFactory factory = new TestFactory();
    Assertions.assertEquals(KeyAndCertificateHandler.class, factory.handler());
  }

  private TestConfig getFullConfig() {

    final DefaultValuePolicyCheckerConfiguration checkerConfig = new DefaultValuePolicyCheckerConfiguration();
    checkerConfig.setRules(List.of(DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig.builder()
        .allowAnyValue(false)
        .allowedValues(List.of("SE"))
        .attributeType(CertificateAttributeType.RDN)
        .ref("2.5.4.2")
        .build()));
    checkerConfig.setDefaultReply(false);

    final TestConfig config = new TestConfig();
    config.setName("NAME");
    config.setAlgorithmRegistry(AlgorithmRegistrySingleton.getInstance());
    config.setRsaProvider(RsaProviderConfiguration.builder().keySize(2048).build());
    config.setEcProvider(ECProviderConfiguration.builder().curveName("P-256").build());
    config.setProfileConfiguration(new CertificateProfileConfiguration());
    config.setDefaultValuePolicyChecker(checkerConfig);
    config.setServiceName("SERVICE_NAME");
    config.setCaCertificateType(CertificateType.PKC);

    return config;
  }

  private static class TestConfig extends AbstractKeyAndCertificateHandlerConfiguration {

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return TestFactory.class.getName();
    }
  }

  private static class TestFactory extends AbstractKeyAndCertificateHandlerFactory {

    @Override
    @Nonnull
    protected AbstractKeyAndCertificateHandler createKeyAndCertificateHandler(
        @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
        @Nullable final BeanLoader beanLoader,
        @Nonnull final List<KeyProvider> keyProviders,
        @Nonnull final AttributeMapper attributeMapper,
        @Nonnull final AlgorithmRegistry algorithmRegistry,
        @Nullable final CertificateProfileConfiguration profileConfiguration) throws IllegalArgumentException {

      return new TestHandler(keyProviders, attributeMapper, algorithmRegistry);
    }

    public Class<KeyAndCertificateHandler> handler() {
      return this.getHandlerType();
    }
  }

  private static class TestHandler extends AbstractKeyAndCertificateHandler {

    public TestHandler(
        @Nonnull final List<KeyProvider> keyProviders,
        @Nonnull final AttributeMapper attributeMapper,
        @Nonnull AlgorithmRegistry algorithmRegistry) {
      super(keyProviders, attributeMapper, algorithmRegistry);
    }

    @Override
    @Nonnull
    protected List<X509Certificate> issueSigningCertificateChain(@Nonnull final PkiCredential signingKeyPair,
        @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
        @Nonnull final List<AttributeMappingData> certAttributes,
        @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
        throws CertificateException {

      return null;
    }

    @Override
    protected void assertCertificateProfileSupported(@Nullable final String certificateProfile)
        throws InvalidRequestException {
    }

  }

}
