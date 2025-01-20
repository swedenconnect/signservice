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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.signature.XMLSignature;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerFactory;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.simple.SimpleKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.simple.ca.BasicCAService;
import se.swedenconnect.signservice.certificate.simple.ca.BasicCAServiceBuilder;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory for creating {@link SimpleKeyAndCertificateHandler} instances.
 */
@Slf4j
public class SimpleKeyAndCertificateHandlerFactory extends AbstractKeyAndCertificateHandlerFactory {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractKeyAndCertificateHandler createKeyAndCertificateHandler(
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
      @Nullable final BeanLoader beanLoader,
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nullable final Map<String, String> algorithmKeyTypes,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nullable final CertificateProfileConfiguration profileConfiguration) throws IllegalArgumentException {

    if (!SimpleKeyAndCertificateHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final SimpleKeyAndCertificateHandlerConfiguration conf =
        SimpleKeyAndCertificateHandlerConfiguration.class.cast(configuration);

    final PkiCredential caCredential = Optional.ofNullable(conf.getCaCredential())
        .map(c -> c.resolvePkiCredential(beanLoader))
        .orElseThrow(() -> new IllegalArgumentException("Missing CA credential"));

    String caSigningAlgorithm = conf.getCaSigningAlgorithm();
    if (StringUtils.isBlank(caSigningAlgorithm)) {
      if ("RSA".equals(caCredential.getPublicKey().getAlgorithm())) {
        caSigningAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
      }
      else if ("EC".equals(caCredential.getPublicKey().getAlgorithm())) {
        caSigningAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
      }
      else {
        throw new IllegalArgumentException("No CA signing algorithm given - could not apply defaults");
      }
      log.info("Setting CA signing algorithm to default value: {}", caSigningAlgorithm);
    }

    final String crlDpPath = Optional.ofNullable(conf.getCrlDpPath())
      .filter(StringUtils::isNotBlank)
      .orElse(null);

    final String crlDp = Optional.ofNullable(conf.getCrlDpUrl())
      .filter(StringUtils::isNotBlank)
      .orElseGet(() -> {
        Optional.ofNullable(crlDpPath)
          .orElseThrow(() -> new IllegalArgumentException("CRL distributions point path must be set when CRL "
            + "distribution point URL is not set"));
        return String.format("%s%s", Optional.ofNullable(conf.getBaseUrl())
          .filter(StringUtils::isNotBlank)
          .orElseThrow(() -> new IllegalArgumentException("Base URL must be set to form CRL Distribution point "
            + "based on path")), crlDpPath);
      });

    final String crlFileLocation = Optional.ofNullable(conf.getCrlFileLocation())
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new IllegalArgumentException("CRL file location must be set"));

    // Set up a CA service
    //
    BasicCAService caService = null;
    try {
      final BasicCAServiceBuilder builder =
          BasicCAServiceBuilder.getInstance(caCredential, crlDp, caSigningAlgorithm, crlFileLocation);
      if (conf.getCertValidity() != null) {
        builder.certificateValidity(conf.getCertValidity());
      }
      if (conf.getCrlValidity() != null) {
        builder.crlValidity(conf.getCrlValidity());
      }
      caService = builder.build();
      if (profileConfiguration != null) {
        caService.setProfileConfiguration(profileConfiguration);
      }
    }
    catch (final IOException e) {
      final String msg = String.format("Failed to set up a CA repository - %s", e.getMessage());
      log.info("{}", msg, e);
      throw new IllegalArgumentException(msg, e);
    }
    catch (final NoSuchAlgorithmException | CRLException | CertificateException e) {
      final String msg = "Failed to set up a CA service - " + e.getMessage();
      log.info("{}", msg, e);
      throw new IllegalArgumentException(msg, e);
    }

    return new SimpleKeyAndCertificateHandler(
        keyProvider, algorithmKeyTypes, attributeMapper, algorithmRegistry, caService, crlDpPath);
  }

}
