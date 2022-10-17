/*
 * Copyright 2022 Litsec AB
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
package se.swedenconnect.signservice.application;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.audit.AuditEventIds;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The main application bean. The SignService engine manager is responsible of routing every call to a matching engine.
 */
@Slf4j
public class DefaultSignServiceEngineManager implements SignServiceEngineManager {

  /** The SignService engines. */
  private final List<SignServiceEngine> engines;

  /** The system audit logger. */
  private final AuditLogger systemAuditLogger;

  /**
   * Constructor accepting the list of SignService engines that are configured for the SignService application.
   *
   * @param engines a list of SignService engines
   * @param systemAuditLogger the system audit logger
   */
  public DefaultSignServiceEngineManager(
      @Nonnull final List<SignServiceEngine> engines, @Nonnull final AuditLogger systemAuditLogger) {
    this.engines = Objects.requireNonNull(engines, "engines must not be null");
    this.systemAuditLogger = Objects.requireNonNull(systemAuditLogger, "systemAuditLogger must not be null");

    this.systemAuditLogger.auditLog(AuditEventIds.EVENT_SYSTEM_STARTED, (b) -> b.build());
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HttpRequestMessage processRequest(
      @Nonnull final HttpServletRequest request, @Nonnull final HttpServletResponse response)
      throws UnrecoverableSignServiceException {

    log.debug("Received {} request [path: '{}', client-ip: '{}']",
        request.getMethod(), request.getRequestURI(), request.getRemoteAddr());

    // Find an engine that can process the request ...
    //
    final SignServiceEngine engine = this.engines.stream()
        .filter(e -> e.canProcess(request))
        .findFirst()
        .orElse(null);

    if (engine == null) {
      log.info("No SignServiceEngine can service {} request on {}", request.getMethod(), request.getRequestURI());
      this.systemAuditLogger.auditLog(AuditEventIds.EVENT_SYSTEM_NOTFOUND,
          (b) -> b
              .parameter("path", request.getRequestURI())
              .parameter("method", request.getMethod())
              .build());

      throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.NOT_FOUND, "No such resource");
    }
    log.debug("Engine '{}' is processing {} request [path: '{}']", engine.getName(), request.getMethod(),
        request.getRequestURI());

    // Hand the request over to the engine ...
    //
    try {
      final HttpRequestMessage result = engine.processRequest(request, response);

      if (result == null) {
        // If the result from the processing is null, it means that the engine, or any of its
        // sub-components, has served a resource and written it to the HttpServletResponse. All we
        // have to do now is commit the response ...
        //
        log.debug("Engine '{}' has served resource, flushing buffer ...", engine.getName());
        response.flushBuffer();
        return null;
      }
      else {
        if ("GET".equals(result.getMethod())) {
          log.debug("Engine '{}' redirecting to: {}", engine.getName(), result.getUrl());
        }
        else {
          log.debug("Engine '{}' posting to: {}", engine.getName(), result.getUrl());
        }
        return result;
      }
    }
    catch (final IOException e) {
      final String msg = String.format("Failed to write resource %s - %s", request.getRequestURI(), e.getMessage());
      log.info("{}", msg, e);

      this.systemAuditLogger.auditLog(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, (b) -> b
          .parameter("engine", engine.getName())
          .parameter("error-code", UnrecoverableErrorCodes.INTERNAL_ERROR)
          .parameter("message", msg)
          .build());

      throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.INTERNAL_ERROR, msg, e);
    }
    catch (final UnrecoverableSignServiceException e) {
      final String msg = String.format("Engine '%s' reported error '%s' when processing request received on '%s' - %s",
          engine.getName(), e.getErrorCode(), request.getRequestURI(), e.getMessage());
      log.info("{}", msg, e);

      this.systemAuditLogger.auditLog(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, (b) -> b
          .parameter("engine", engine.getName())
          .parameter("error-code", e.getErrorCode())
          .parameter("message", msg)
          .build());

      throw e;
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<SignServiceEngine> getEngines() {
    return Collections.unmodifiableList(this.engines);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuditLogger getSystemAuditLogger() {
    return this.systemAuditLogger;
  }

}
