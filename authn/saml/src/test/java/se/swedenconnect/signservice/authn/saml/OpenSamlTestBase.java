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
package se.swedenconnect.signservice.authn.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.BeforeAll;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter;
import org.w3c.dom.Element;

import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.DefaultSecurityConfiguration;

/**
 * Abstract base class that initializes OpenSAML for test classes.
 */
public abstract class OpenSamlTestBase {

  /**
   * Initializes the OpenSAML library.
   *
   * @throws Exception for init errors
   */
  @BeforeAll
  public static void initializeOpenSAML() throws Exception {
    final OpenSAMLInitializer bootstrapper = OpenSAMLInitializer.getInstance();
    if (!bootstrapper.isInitialized()) {
      bootstrapper.initialize(
          new OpenSAMLSecurityDefaultsConfig(new DefaultSecurityConfiguration()),
          new OpenSAMLSecurityExtensionConfig());
    }
  }

  /**
   * Loads a {@link KeyStore} based on the given arguments.
   *
   * @param keyStorePath the path to the key store
   * @param keyStorePassword the key store password
   * @param keyStoreType the type of the keystore (if {@code null} the default keystore type will be assumed)
   * @return a {@code KeyStore} instance
   * @throws KeyStoreException for errors loading the keystore
   * @throws IOException for IO errors
   */
  public static KeyStore loadKeyStore(final String keyStorePath, final String keyStorePassword,
      final String keyStoreType) throws KeyStoreException, IOException {
    return loadKeyStore(new FileInputStream(keyStorePath), keyStorePassword, keyStoreType);
  }

  public static KeyStore loadKeyStore(
      final InputStream keyStoreStream, final String keyStorePassword, final String keyStoreType)
      throws KeyStoreException, IOException {
    try {
      final KeyStore keyStore =
          keyStoreType != null ? KeyStore.getInstance(keyStoreType) : KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(keyStoreStream, keyStorePassword.toCharArray());
      return keyStore;
    }
    catch (NoSuchAlgorithmException | CertificateException e) {
      throw new KeyStoreException(e);
    }
  }

  public static X509Credential loadKeyStoreCredential(final InputStream keyStoreStream, final String keyStorePassword,
      final String alias, final String keyPassword) throws KeyStoreException, IOException {
    final KeyStore keyStore = loadKeyStore(keyStoreStream, keyStorePassword, "jks");
    return new KeyStoreX509CredentialAdapter(keyStore, alias, keyPassword.toCharArray());
  }

  /**
   * Unmarshalls the supplied input stream into the given type.
   *
   * @param inputStream the input stream of the XML resource
   * @param targetClass the required class
   * @param <T> the type
   * @return an {@code XMLObject} of the given type
   * @throws XMLParserException for XML parsing errors
   * @throws UnmarshallingException for unmarshalling errors
   */
  public static <T extends XMLObject> T unmarshall(final InputStream inputStream, final Class<T> targetClass)
      throws XMLParserException, UnmarshallingException {
    final Element elm = XMLObjectProviderRegistrySupport.getParserPool().parse(inputStream).getDocumentElement();
    return targetClass.cast(XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm));
  }

}
