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

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.operator.OperatorCreationException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.client.impl.ProxyCMCClientHttpConnector;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerFactory;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.cmc.CMCKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.cmc.CertificateRequestFormat;
import se.swedenconnect.signservice.certificate.cmc.RemoteCaInformation;
import se.swedenconnect.signservice.certificate.cmc.SignServiceCMCClient;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory class for {@link CMCKeyAndCertificateHandler}.
 */
@Slf4j
public class CMCKeyAndCertificateHandlerFactory extends AbstractKeyAndCertificateHandlerFactory {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractKeyAndCertificateHandler createKeyAndCertificateHandler(
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
      @Nullable final BeanLoader beanLoader,
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nonnull final Map<String, String> algorithmKeyTypeMap,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nullable final CertificateProfileConfiguration profileConfiguration) throws IllegalArgumentException {

    if (!CMCKeyAndCertificateHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final CMCKeyAndCertificateHandlerConfiguration conf =
        CMCKeyAndCertificateHandlerConfiguration.class.cast(configuration);

    final String requestURL = Optional.ofNullable(conf.getCmcRequestUrl())
        .filter(s -> StringUtils.isNotBlank(s))
        .orElseThrow(() -> new IllegalArgumentException("Missing CMC request URL"));

    final PkiCredential clientCredential = Optional.ofNullable(conf.getCmcClientCredential())
        .map(c -> c.resolvePkiCredential(beanLoader))
        .orElseThrow(() -> new IllegalArgumentException("Missing CMC client credential"));

    String signingAlgorithm = conf.getCmcSigningAlgorithm();
    if (StringUtils.isBlank(signingAlgorithm)) {
      if ("RSA".equals(clientCredential.getPublicKey().getAlgorithm())) {
        signingAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
      }
      else if ("EC".equals(clientCredential.getPublicKey().getAlgorithm())) {
        signingAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
      }
      else {
        throw new IllegalArgumentException("No CMC signing algorithm given - could not apply defaults");
      }
    }

    final X509Certificate responderCertificate = Optional.ofNullable(conf.getCmcResponderCertificate())
        .orElseThrow(() -> new IllegalArgumentException("Missing CMC responder certificate"));

    final RemoteCaInformation caInformation = Optional.ofNullable(conf.getRemoteCaInfo())
        .orElseThrow(() -> new IllegalArgumentException("Missing remote CA information"));

    try {
      final SignServiceCMCClient cmcClient = new SignServiceCMCClient(
          requestURL, clientCredential, signingAlgorithm, responderCertificate, caInformation);
      cmcClient.setCmcClientHttpConnector(new ProxyCMCClientHttpConnector(conf.getCmcClientProxy()));
      if (conf.getProfileConfiguration() != null) {
        cmcClient.setProfileConfiguration(profileConfiguration);
      }

      final CertificateRequestFormat certificateRequestFormat = conf.getCertificateRequestFormat() == null
          ? CertificateRequestFormat.pkcs10
          : conf.getCertificateRequestFormat();

      return new CMCKeyAndCertificateHandler(keyProvider, algorithmKeyTypeMap, attributeMapper, algorithmRegistry,
          cmcClient, certificateRequestFormat);
    }
    catch (final CertificateEncodingException | MalformedURLException | NoSuchAlgorithmException
        | OperatorCreationException e) {
      log.warn("Failed to create CMC client - {}", e.getMessage(), e);
      throw new IllegalArgumentException("Failed to create CMC client", e);
    }

  }

}
