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
package se.swedenconnect.signservice.certificate.cmc.config;

import jakarta.annotation.Nonnull;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration.DefaultValuePolicyCheckerConfiguration;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.CredentialContainerConfiguration;
import se.swedenconnect.signservice.certificate.cmc.CMCKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.cmc.RemoteCaInformation;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfigurationProperties;
import se.swedenconnect.signservice.core.config.PkiCredentialFactorySingleton;

import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for CMCKeyAndCertificateHandlerFactory.
 */
public class CMCKeyAndCertificateHandlerFactoryTest {

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
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
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();
    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testFullConf() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof CMCKeyAndCertificateHandler);
    Assertions.assertEquals("NAME", handler.getName());
  }

  @Test
  public void testWithDefaults() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setName(null);
    config.setAlgorithmRegistry(null);
    config.setProfileConfiguration(null);
    config.setDefaultValuePolicyChecker(null);
    config.setServiceName(null);
    config.setCaSupportedCertificateTypes(null);
    config.setCmcSigningAlgorithm(null);

    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    final KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertTrue(handler instanceof CMCKeyAndCertificateHandler);
    Assertions.assertEquals(CMCKeyAndCertificateHandler.class.getSimpleName(), handler.getName());

    final PkiCredentialConfigurationProperties ecProps = this.getCmcClientCredentialProperties();
    ecProps.getJks().getKey().setAlias("cmc-ec");
    config.setCmcClientCredential(new PkiCredentialConfiguration(ecProps));

    final KeyAndCertificateHandler handler2 = factory.create(config);
    Assertions.assertTrue(handler2 instanceof CMCKeyAndCertificateHandler);
  }

  @Test
  public void testMissingRequestUrl() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCmcRequestUrl(null);
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing CMC request URL");
  }

  @Test
  public void testMissingClientCredentials() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCmcClientCredential(null);
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing CMC client credential");
  }

  @Test
  public void testMissingUnknownClientCredentials() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCmcSigningAlgorithm(null);

    final PkiCredential cred = Mockito.mock(PkiCredential.class);
    final PublicKey pk = Mockito.mock(PublicKey.class);
    Mockito.when(pk.getAlgorithm()).thenReturn("UNKNOWN");
    Mockito.when(cred.getPublicKey()).thenReturn(pk);

    config.setCmcClientCredential(new PkiCredentialConfiguration(cred));

    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No CMC signing algorithm given - could not apply defaults");
  }

  @Test
  public void testMissingResponderCertificate() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCmcResponderCertificate(null);
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing CMC responder certificate");
  }

  @Test
  public void testMissingCaInfo() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setRemoteCaInfo(null);
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing remote CA information");
  }

  @Test
  public void testFailedCreateClient() throws Exception {
    final CMCKeyAndCertificateHandlerConfiguration config = this.getFullConfig();
    config.setCmcRequestUrl("not-a-valid-url");
    final CMCKeyAndCertificateHandlerFactory factory = new CMCKeyAndCertificateHandlerFactory();

    assertThatThrownBy(() -> factory.create(config)).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Failed to create CMC client");
  }

  private CMCKeyAndCertificateHandlerConfiguration getFullConfig() throws Exception {

    final DefaultValuePolicyCheckerConfiguration checkerConfig = new DefaultValuePolicyCheckerConfiguration();
    checkerConfig.setRules(List.of(DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig.builder()
        .allowAnyValue(false)
        .allowedValues(List.of("SE"))
        .attributeType(CertificateAttributeType.RDN)
        .ref("2.5.4.2")
        .build()));
    checkerConfig.setDefaultReply(false);

    final CMCKeyAndCertificateHandlerConfiguration config = new CMCKeyAndCertificateHandlerConfiguration();
    config.setName("NAME");
    config.setAlgorithmRegistry(AlgorithmRegistrySingleton.getInstance());
    config.setAlgorithmKeyType(AbstractKeyAndCertificateHandler.DEFAULT_ALGORITHM_KEY_TYPES);
    config.setKeyProvider(CredentialContainerConfiguration.builder()
        .securityProvider("BC")
        .build());
    config.setProfileConfiguration(new CertificateProfileConfiguration());
    config.setDefaultValuePolicyChecker(checkerConfig);
    config.setServiceName("SERVICE_NAME");
    config.setCmcRequestUrl("https://cmc.example.com");
    config.setCmcClientCredential(new PkiCredentialConfiguration(this.getCmcClientCredentialProperties()));
    config.setCmcSigningAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    config.setCmcResponderCertificate(this.getCmcResponderCert());
    config.setRemoteCaInfo(RemoteCaInformation.builder()
        .caAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256)
        .caCertificateChain(List.of(this.getCmcCaCert()))
        .build());
    return config;
  }

  private PkiCredentialConfigurationProperties getCmcClientCredentialProperties() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setJks(new StoreCredentialConfigurationProperties());
    props.getJks().setStore(new StoreConfigurationProperties());
    props.getJks().getStore().setLocation("classpath:cmc-client.jks");
    props.getJks().getStore().setPassword("secret");
    props.getJks().setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    props.getJks().getKey().setAlias("cmc");
    props.getJks().getKey().setKeyPassword("secret");
    return props;
  }

  @SuppressWarnings("unused")
  private PkiCredential getCmcClientCredential() throws Exception {
    return PkiCredentialFactorySingleton.getInstance().getPkiCredentialFactory()
        .createCredential(this.getCmcClientCredentialProperties());
  }

  private X509Certificate getCmcResponderCert() throws Exception {
    return X509Utils.decodeCertificate(new ClassPathResource("cmc-responder.crt").getInputStream());
  }

  private X509Certificate getCmcCaCert() throws Exception {
    return X509Utils.decodeCertificate(new ClassPathResource("cmc-ca.crt").getInputStream());
  }
}
