/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.certificate.simple.config;

import jakarta.annotation.Nonnull;
import org.apache.commons.io.FileUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration.DefaultValuePolicyCheckerConfiguration;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.CredentialContainerConfiguration;
import se.swedenconnect.signservice.certificate.simple.SimpleKeyAndCertificateHandler;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfigurationProperties;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Security;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for SimpleKeyAndCertificateHandlerFactory.
 */
public class SimpleKeyAndCertificateHandlerFactoryTest {

  private static final String CRL_DIR = "target/test/ca-repo";

  @BeforeAll
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @AfterAll
  public static void clean() throws Exception {
    FileUtils.deleteDirectory(new File(CRL_DIR));
  }

  @Test
  public void testBadConfigType() {
    final HandlerConfiguration<KeyAndCertificateHandler> config;
    config = new AbstractKeyAndCertificateHandlerConfiguration() {
      @Nonnull
      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();
    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testFullConf() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof SimpleKeyAndCertificateHandler);
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testDefaultSigningAlgo() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaSigningAlgorithm(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof SimpleKeyAndCertificateHandler);

    // The same for EC
    final SimpleKeyAndCertificateHandlerConfiguration config2 = this.getFullConfig();
    config.getCaCredential().getProps().setAlias("ec-ca");

    final KeyAndCertificateHandler handler2 = factory.create(config2);
    Assertions.assertTrue(handler2 instanceof SimpleKeyAndCertificateHandler);
  }

  @Test
  public void testDefaultValidity() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCertValidity(null);
    config.setCrlValidity(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof SimpleKeyAndCertificateHandler);
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testDefaultProfile() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setProfileConfiguration(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof SimpleKeyAndCertificateHandler);
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testCRLDistributionPointUrl() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final Field crlDp = config.getClass().getDeclaredField("crlDpPath");
    crlDp.setAccessible(true);
    crlDp.set(config, null);
    final Field crlDpUlr = config.getClass().getDeclaredField("crlDpUrl");
    crlDpUlr.setAccessible(true);
    crlDpUlr.set(config, "https://example.com/crl");
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();
    factory.create(config);
  }

  @Test
  public void testMissingCrlDp() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final Field crlDp = config.getClass().getDeclaredField("crlDpPath");
    crlDp.setAccessible(true);
    crlDp.set(config, null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CRL distributions point path must be set when CRL distribution point URL is not set");
  }

  @Test
  public void testMissingBaseUrl() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final Field crlDp = config.getClass().getDeclaredField("baseUrl");
    crlDp.setAccessible(true);
    crlDp.set(config, null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Base URL must be set to form CRL Distribution point based on path");
  }

  @Test
  public void testBadAlgorithm() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaSigningAlgorithm("http://not.a.valid.alg");
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Failed to set up a CA service - Unsupported algorithm: http://not.a.valid.alg");
  }

  @Test
  public void testIOError() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCrlFileLocation("target");
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to set up a CA repository - ")
        .hasCauseInstanceOf(IOException.class);
  }

  @Test
  public void testMissingCrlFileLocation() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCrlFileLocation(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CRL file location must be set");
  }

  @Test
  public void testMissingCaCredential() {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaCredential(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing CA credential");
  }

  private SimpleKeyAndCertificateHandlerConfiguration getFullConfig() {

    final DefaultValuePolicyCheckerConfiguration checkerConfig = new DefaultValuePolicyCheckerConfiguration();
    checkerConfig.setRules(List.of(DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig.builder()
        .allowAnyValue(false)
        .allowedValues(List.of("SE"))
        .attributeType(CertificateAttributeType.RDN)
        .ref("2.5.4.2")
        .build()));
    checkerConfig.setDefaultReply(false);

    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();
    config.setName("NAME");
    config.setAlgorithmRegistry(AlgorithmRegistrySingleton.getInstance());
    config.setAlgorithmKeyType(AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES);
    config.setKeyProvider(CredentialContainerConfiguration.builder()
        .securityProvider("BC")
        .build());
    config.setProfileConfiguration(new CertificateProfileConfiguration());
    config.setDefaultValuePolicyChecker(checkerConfig);
    config.setServiceName("SERVICE_NAME");

    config.setBaseUrl("https://www.example.com/sign");
    config.setCaCredential(new PkiCredentialConfiguration(this.getCaCredentialProperties()));
    config.setCaSigningAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    config.setCertValidity(Duration.ofDays(365));
    config.setCrlValidity(Duration.ofDays(2));
    config.setCrlDpPath("/ca/crl/cacrl.crl");
    config.setCrlFileLocation(CRL_DIR + "/testca.crl");

    return config;
  }

  private PkiCredentialConfigurationProperties getCaCredentialProperties() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource("classpath:test-ca.jks");
    props.setPassword("secret".toCharArray());
    props.setAlias("rsa-ca");
    props.setKeyPassword("secret".toCharArray());
    return props;
  }

}
