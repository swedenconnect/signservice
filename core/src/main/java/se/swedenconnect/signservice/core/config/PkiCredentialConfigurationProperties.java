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
package se.swedenconnect.signservice.core.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Class for handling configuration of credentials. It extends the
 * {@link se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties} for backwards
 * compatibility reasons.
 *
 * @author Martin Lindström
 */
@Deprecated(since = "1.2.0", forRemoval = true)
public class PkiCredentialConfigurationProperties
    extends se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties {

  /**
   * The name of the credential.
   */
  @Getter
  @Setter
  private String name;

  /**
   * A resource holding the certificate part of the credential (optional since the certificate may be part of a
   * keystore).
   */
  @Getter
  @Setter
  private String certificate;

  /**
   * A list of resources holding the certificate chain that part of the credential (optional since the certificate may
   * be part of a keystore). If used, the entity certificate must be the first element.
   */
  @Getter
  @Setter
  private List<String> certificates;

  /**
   * A resource holding the private key part of the credential (optional since the key may be part of a keystore).
   */
  @Getter
  @Setter
  private String privateKey;

  /**
   * A resource to the keystore containing the credential.
   */
  @Getter
  @Setter
  private String resource;

  /**
   * The keystore password.
   */
  @Getter
  @Setter
  private char[] password;

  /**
   * The type of keystore.
   */
  @Getter
  @Setter
  private String type;

  /**
   * The name of the security provider to use when creating the KeyStore instance.
   */
  @Getter
  @Setter
  private String provider;

  /**
   * The PKCS#11 configuration file to use.
   */
  @Getter
  @Setter
  private String pkcs11Configuration;

  /**
   * The keystore alias to the entry holding the key pair.
   */
  @Getter
  @Setter
  private String alias;

  /**
   * The password to unlock the private key from the keystore.
   */
  @Getter
  @Setter
  private char[] keyPassword;

  /**
   * Assigns the PIN (which is the same as {@code keyPassword}). Used mainly for PKCS#11.
   *
   * @param pin the PIN
   */
  public void setPin(final char[] pin) {
    this.setKeyPassword(pin);
  }

  /**
   * Gets the PIN (which is the same as {@code keyPassword}). Used mainly for PKCS#11.
   *
   * @return the PIN
   */
  public char[] getPin() {
    return this.getKeyPassword();
  }

  /**
   * Predicate that returns {@code true} if this object is "empty", meaning that no settings have been applied.
   *
   * @return true if empty and false otherwise
   */
  public boolean isEmpty() {
    return this.getBundle() == null
        && this.getPem() == null
        && this.getJks() == null
        && StringUtils.isEmpty(this.name)
        && StringUtils.isEmpty(this.name)
        && StringUtils.isEmpty(this.certificate)
        && (this.certificates == null || this.certificates.isEmpty())
        && StringUtils.isEmpty(this.privateKey)
        && StringUtils.isEmpty(this.resource)
        && (this.password == null || this.password.length == 0)
        && StringUtils.isEmpty(this.type)
        && StringUtils.isEmpty(this.provider)
        && StringUtils.isEmpty(this.pkcs11Configuration)
        && StringUtils.isEmpty(this.alias)
        && (this.keyPassword == null || this.keyPassword.length == 0);
  }

  /**
   * Predicate that tells whether any of the deprecated properties are set.
   *
   * @return {@code true} if deprecated properties are set
   */
  public boolean hasDeprecatedProperties() {
    return !StringUtils.isEmpty(this.name)
        || !StringUtils.isEmpty(this.certificate)
        || this.certificates != null
        || !StringUtils.isEmpty(this.privateKey)
        || !StringUtils.isEmpty(this.resource)
        || this.password != null
        || !StringUtils.isEmpty(this.type)
        || !StringUtils.isEmpty(this.provider)
        || !StringUtils.isEmpty(this.pkcs11Configuration)
        || !StringUtils.isEmpty(this.alias)
        || this.keyPassword != null;
  }

  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (this.isEmpty()) {
      throw new IllegalArgumentException("Missing configuration");
    }
    this.removeDeprecated();
  }

  /**
   * Moves deprecated properties into the pem or jks properties.
   *
   * @throws IllegalArgumentException for invalid configuration
   */
  public void removeDeprecated() throws IllegalArgumentException {
    if (!this.hasDeprecatedProperties()) {
      return;
    }
    // Be forgiving if only name is assigned ...
    final String name = this.name;
    this.name = null;
    if (!StringUtils.isEmpty(name) && !this.hasDeprecatedProperties()) {
      Optional.ofNullable(this.getJks()).ifPresent(j -> j.setName(name));
      Optional.ofNullable(this.getPem()).ifPresent(p -> p.setName(name));
      return;
    }

    if (this.getJks() != null || this.getPem() != null || this.getBundle() != null) {
      throw new IllegalArgumentException("Invalid PKI credential configuration");
    }
    if (this.privateKey != null) {
      if (this.resource != null || !StringUtils.isEmpty(this.alias) || !StringUtils.isEmpty(this.type)
          || this.password != null || !StringUtils.isEmpty(this.pkcs11Configuration) || !StringUtils.isEmpty(
          this.provider)) {
        throw new IllegalArgumentException("Invalid PKI credential configuration - Can not configure both PEM and JKS");
      }

      this.setPem(new PemCredentialConfigurationProperties());
      this.getPem().setPrivateKey(this.privateKey);
      this.privateKey = null;
      this.getPem().setCertificates(this.parseCertificates());
      Optional.ofNullable(name).ifPresent(n -> this.getPem().setName(n));
      Optional.ofNullable(this.keyPassword).ifPresent(p -> {
        this.getPem().setKeyPassword(new String(p));
        this.keyPassword = null;
      });
    }
    else {
      this.setJks(new StoreCredentialConfigurationProperties());
      this.getJks().setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
      this.getJks().setStore(new StoreConfigurationProperties());
      Optional.ofNullable(name).ifPresent(n -> this.getJks().setName(n));

      Optional.ofNullable(this.resource).ifPresent(r -> {
        this.getJks().getStore().setLocation(r);
        this.resource = null;
      });
      Optional.ofNullable(this.password).ifPresent(p -> {
        this.getJks().getStore().setPassword(new String(p));
        this.password = null;
      });
      Optional.ofNullable(this.type).ifPresent(t -> {
        this.getJks().getStore().setType(t);
        this.type = null;
      });
      Optional.ofNullable(this.provider).ifPresent(p -> {
        this.getJks().getStore().setProvider(p);
        this.provider = null;
      });
      Optional.ofNullable(this.pkcs11Configuration).ifPresent(p -> {
        this.getJks().getStore().setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
        this.getJks().getStore().getPkcs11().setConfigurationFile(p);
        this.pkcs11Configuration = null;
      });

      Optional.ofNullable(this.alias).ifPresent(a -> {
        this.getJks().getKey().setAlias(a);
        this.alias = null;
      });
      Optional.ofNullable(this.keyPassword).ifPresent(p -> {
        this.getJks().getKey().setKeyPassword(new String(p));
        this.keyPassword = null;
      });
      this.getJks().getKey().setCertificates(this.parseCertificates());
    }
  }

  private String parseCertificates() throws IllegalArgumentException {
    try {
      if (this.certificate != null) {
        if (this.certificates != null && !this.certificates.isEmpty()) {
          throw new IllegalArgumentException("Can not specify both certificate and certificates");
        }
        return this.certificate;
      }
      if (this.certificates != null && !this.certificates.isEmpty()) {
        if (this.certificates.size() == 1) {
          return this.certificates.get(0);
        }
        final StringWriter sw = new StringWriter();
        final ConfigurationResourceLoader loader = new DefaultConfigurationResourceLoader();
        try (final PemWriter pemWriter = new PemWriter(sw)) {
          for (final String c : this.certificates) {
            final X509Certificate certObj;
            try (final InputStream is = loader.getStream(c)) {
              certObj = X509Utils.decodeCertificate(is);
            }
            final PemObjectGenerator gen = new JcaMiscPEMGenerator(certObj);
            pemWriter.writeObject(gen);
          }
        }
        this.certificates = null;
        sw.flush();
        return sw.toString();
      }
      return null;
    }
    catch (final IOException | CertificateException e) {
      throw new IllegalArgumentException("Invalid PKI credential configuration", e);
    }
    finally {
      this.certificate = null;
      this.certificates = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    final PkiCredentialConfigurationProperties that = (PkiCredentialConfigurationProperties) o;
    return Objects.equals(this.name, that.name) && Objects.equals(this.certificate, that.certificate)
        && Objects.equals(this.certificates, that.certificates) && Objects.equals(this.privateKey,
        that.privateKey) && Objects.equals(this.resource, that.resource) && Objects.deepEquals(this.password,
        that.password) && Objects.equals(this.type, that.type) && Objects.equals(this.provider, that.provider)
        && Objects.equals(this.pkcs11Configuration, that.pkcs11Configuration) && Objects.equals(this.alias,
        that.alias) && Objects.deepEquals(this.keyPassword, that.keyPassword);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.name, this.certificate, this.certificates, this.privateKey,
        this.resource, Arrays.hashCode(this.password), this.type, this.provider, this.pkcs11Configuration, this.alias,
        Arrays.hashCode(this.keyPassword));
  }

}
