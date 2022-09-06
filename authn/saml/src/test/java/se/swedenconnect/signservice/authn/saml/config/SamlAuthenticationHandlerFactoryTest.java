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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Element;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.DefaultSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.OpenSamlTestBase;
import se.swedenconnect.signservice.authn.saml.SwedenConnectSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.MetadataConfiguration.ContactPersonConfig;
import se.swedenconnect.signservice.authn.saml.config.MetadataConfiguration.OrganizationConfig;
import se.swedenconnect.signservice.authn.saml.config.MetadataConfiguration.UIInfoConfig;
import se.swedenconnect.signservice.authn.saml.config.MetadataConfiguration.UIInfoConfig.UIInfoLogo;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * Test cases for SamlAuthenticationHandlerFactory.
 */
public class SamlAuthenticationHandlerFactoryTest extends OpenSamlTestBase {

  private static final String ENTITY_ID = "https://www.example.com/sp";
  private static final String BASE_URL = "https://www.example.com";
  private static final String ASSERTION_CONSUMER_PATH = "/saml/sso";
  private static final String METADATA_PUBLISHING_PATH = "/saml/metadata";

  private KeyStore keyStore;

  public SamlAuthenticationHandlerFactoryTest() throws Exception {
    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean(
        new ClassPathResource("keys.jks"), "secret".toCharArray());
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
  }

  @Test
  public void testMissingConfig() {
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration for creating AuthenticationHandler instances");
  }

  @Test
  public void testOtherConfig() {
    final HandlerConfiguration<AuthenticationHandler> conf = new AbstractHandlerConfiguration<AuthenticationHandler>() {

      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testCreateSwedenConnect() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(SwedenConnectSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testCreateDefault() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSamlType(null);
    conf.setPreferredBinding("redirect");
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(DefaultSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testUseDefaultCredential() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setDefaultCredential(conf.getSignatureCredential());
    conf.setSignatureCredential(null);
    conf.setDecryptionCredential(null);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(SwedenConnectSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testUseNoCredential() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSamlType(null);
    conf.setSignatureCredential(null);
    conf.setDecryptionCredential(null);
    conf.setRequireEncryptedAssertions(false);
    conf.setSignAuthnRequests(false);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(DefaultSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testCreateMetadataConfig() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.getSpPaths().setAdditionalAssertionConsumerPath("/saml/additional");

    final ResponseValidationSettings rvs = new ResponseValidationSettings();
    rvs.setRequireSignedAssertions(true);
    conf.setResponseValidation(rvs);

    final MetadataConfiguration md = new MetadataConfiguration();
    md.setAuthnRequestsSigned(true);
    md.setEntityCategories(Arrays.asList("http://id.elegnamnden.se/st/1.0/sigservice",
        "http://id.elegnamnden.se/ec/1.0/loa3-pnr"));
    md.setServiceNames(Arrays.asList(new LocalizedString("demo", Locale.ENGLISH)));

    final UIInfoConfig ui = new UIInfoConfig();
    ui.setDisplayNames(Arrays.asList(
        new LocalizedString("en-DemoApp"), new LocalizedString("sv-DemoApp")));
    ui.setDescriptions(Arrays.asList(
        new LocalizedString("en-DemoApp"), new LocalizedString("sv-DemoApp")));
    final UIInfoLogo logo = new UIInfoLogo();
    logo.setHeight(100);
    logo.setWidth(100);
    logo.setPath("/images/logo.svg");
    ui.setLogos(Arrays.asList(logo));
    md.setUiInfo(ui);

    final Map<ContactPersonTypeEnumeration, ContactPersonConfig> map = new HashMap<>();
    final ContactPersonConfig cpc = new ContactPersonConfig();
    cpc.setCompany("Sweden Connect");
    cpc.setEmailAddress("operations@swedenconnect.se");
    map.put(ContactPersonTypeEnumeration.TECHNICAL, cpc);
    map.put(ContactPersonTypeEnumeration.SUPPORT, cpc);
    md.setContactPersons(map);

    final OrganizationConfig oc = new OrganizationConfig();
    oc.setNames(Arrays.asList(new LocalizedString("en-Sweden Connect"), new LocalizedString("sv-Sweden Connect")));
    md.setOrganization(oc);

    conf.setMetadata(md);

    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(SwedenConnectSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testSeveralMetadataProviders() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();

    final MetadataProviderConfiguration mpc = new MetadataProviderConfiguration();
    mpc.setUrl("https://eid.svelegtest.se/metadata/mdx/role/idp.xml");
    conf.setMetadataProviders(Arrays.asList(mpc, conf.getMetadataProviders().get(0)));

    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(SwedenConnectSamlAuthenticationHandler.class.isInstance(handler));
  }

  @Test
  public void testIllegalProviderConf() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();

    final MetadataProviderConfiguration mpc = new MetadataProviderConfiguration();
    mpc.setUrl("https://eid.svelegtest.se/metadata/mdx/role/idp.xml");
    mpc.setFile("src/main/resources/idp-metadata.xml");
    conf.setMetadataProviders(Arrays.asList(mpc));

    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Illegal metadata provider configuration - Both url and file are set");

    conf.getMetadataProviders().get(0).setFile(null);
    conf.getMetadataProviders().get(0).setUrl(null);
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Illegal metadata provider configuration - url or file must be set");

    conf.setMetadataProviders(null);
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing metadata provider(s) from configuration object");

    conf.setMetadataProviders(Arrays.asList());
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing metadata provider(s) from configuration object");
  }

  @Test
  public void testUseNoCredentialRequireEncryptedAssertions() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSamlType(null);
    conf.setSignatureCredential(null);
    conf.setDecryptionCredential(null);
    conf.setRequireEncryptedAssertions(true);
    conf.setSignAuthnRequests(false);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No decryption (or default) credential specified - required since require-encrypted-assertions is true");
  }

  @Test
  public void testUnknownType() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSamlType("eidas");
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown saml-type - ");
  }

  @Test
  public void testMissingEntityID() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setEntityId(null);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing entityId from configuration object");
  }

  @Test
  public void testMissingSpPaths() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSpPaths(null);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No sp-paths assigned");
  }

  @Test
  public void testMissingBaseUrl() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setSpPaths(new SpUrlConfiguration());
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No sp-paths.base-url setting assigned");
  }

  @Test
  public void testMissingMessageReplayChecker() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setMessageReplayChecker(null);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("message-replay-checker must not be null");
  }

  @Test
  public void testMissingMetadata() throws Exception {
    final SamlAuthenticationHandlerConfiguration conf = this.buildConfiguration();
    conf.setMetadata(null);
    final SamlAuthenticationHandlerFactory factory = new SamlAuthenticationHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing metadata configuration");
  }

  private SamlAuthenticationHandlerConfiguration buildConfiguration() throws Exception {
    SamlAuthenticationHandlerConfiguration config = new SamlAuthenticationHandlerConfiguration();
    config.setSamlType(SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT);
    config.setEntityId(ENTITY_ID);

    final KeyStoreCredential signCred = new KeyStoreCredential(this.keyStore, "sign", "secret".toCharArray());
    signCred.setName("SIGNING");
    signCred.afterPropertiesSet();
    config.setSignatureCredential(signCred);

    final KeyStoreCredential decryptCred = new KeyStoreCredential(this.keyStore, "encrypt", "secret".toCharArray());
    decryptCred.setName("DECRYPTION");
    decryptCred.afterPropertiesSet();
    config.setDecryptionCredential(decryptCred);

    final SpUrlConfiguration paths = new SpUrlConfiguration();
    paths.setBaseUrl(BASE_URL);
    paths.setAssertionConsumerPath(ASSERTION_CONSUMER_PATH);
    paths.setMetadataPublishingPath(METADATA_PUBLISHING_PATH);
    config.setSpPaths(paths);

    final MetadataProviderConfiguration providerConf = new MetadataProviderConfiguration();
    providerConf.setFile("src/test/resources/idp-metadata.xml");
    config.setMetadataProviders(Arrays.asList(providerConf));

    final MetadataConfiguration metadataConf = new MetadataConfiguration();

    try (final InputStream is = new ClassPathResource("metadata.xml").getInputStream()) {
      final Element elm = XMLObjectProviderRegistrySupport.getParserPool().parse(is).getDocumentElement();
      metadataConf.setTemplate(
          EntityDescriptor.class.cast(XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm)));
    }
    config.setMetadata(metadataConf);

    config.setMessageReplayChecker(new DummyMessageReplayChecker());

    return config;
  }

  private static class DummyMessageReplayChecker implements MessageReplayChecker {

    @Override
    public void checkReplay(final String id) throws MessageReplayException {
    }

  }

}
