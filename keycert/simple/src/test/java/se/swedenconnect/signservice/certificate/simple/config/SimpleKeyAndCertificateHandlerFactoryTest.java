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
package se.swedenconnect.signservice.certificate.simple.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Security;
import java.time.Duration;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
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
  public void testBadConfigType() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new AbstractKeyAndCertificateHandlerConfiguration() {
      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testFullConf() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(SimpleKeyAndCertificateHandler.class.isInstance(handler));
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testDefaultSigningAlgo() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaSigningAlgorithm(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(SimpleKeyAndCertificateHandler.class.isInstance(handler));

    // The same for EC
    config.getCaCredential().getProps().setAlias("ec-ca");

    final KeyAndCertificateHandler handler2 = factory.create(config);
    Assertions.assertTrue(SimpleKeyAndCertificateHandler.class.isInstance(handler2));
  }

  @Test
  public void testDefaultValidity() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCertValidity(null);
    config.setCrlValidity(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(SimpleKeyAndCertificateHandler.class.isInstance(handler));
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testDefaultProfile() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setProfileConfiguration(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(SimpleKeyAndCertificateHandler.class.isInstance(handler));
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

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CRL distributions point path must be set when CRL distribution point URL is not set");
  }

  @Test
  public void testMissingBaseUrl() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final Field crlDp = config.getClass().getDeclaredField("baseUrl");
    crlDp.setAccessible(true);
    crlDp.set(config, null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Base URL must be set to form CRL Distribution point based on path");
  }

  @Test
  public void testBadAlgorithm() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaSigningAlgorithm("http://not.a.valid.alg");
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Failed to set up a CA service - Unsupported algorithm: http://not.a.valid.alg");
  }

  @Test
  public void testIOError() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCrlFileLocation("target");
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to set up a CA repository - ")
        .hasCauseInstanceOf(IOException.class);
  }

  @Test
  public void testMissingCrlFileLocation() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCrlFileLocation(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CRL file location must be set");
  }

  @Test
  public void testMissingCaCredential() throws Exception {
    final SimpleKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCaCredential(null);
    final SimpleKeyAndCertificateHandlerFactory factory = new SimpleKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing CA credential");
  }

  private SimpleKeyAndCertificateHandlerConfiguration getFullConfig() throws Exception {

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
    props.setResource(new ClassPathResource("test-ca.jks"));
    props.setPassword("secret".toCharArray());
    props.setAlias("rsa-ca");
    props.setKeyPassword("secret".toCharArray());
    return props;
  }

}
