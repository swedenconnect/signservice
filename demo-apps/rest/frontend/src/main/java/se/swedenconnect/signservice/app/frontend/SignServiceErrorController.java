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
package se.swedenconnect.signservice.app.frontend;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Application error controller.
 */
@Controller
@ControllerAdvice
@Slf4j
public class SignServiceErrorController extends AbstractErrorController {

  @Setter
  @Autowired
  private MessageSource messageSource;

  @Setter
  @Autowired
  private ObjectMapper objectMapper;

  /**
   * Constructor.
   */
  public SignServiceErrorController() {
    super(new DefaultErrorAttributes());
  }

  /**
   * Error handler.
   *
   * @param request the HTTP request
   * @return a model and view object
   */
  @RequestMapping("/error")
  public ModelAndView handleError(final HttpServletRequest request) {

    final Map<String, Object> errorAttributes = this.getErrorAttributes(request, ErrorAttributeOptions.defaults());

    if (log.isInfoEnabled()) {
      final StringBuffer sb = new StringBuffer();
      for (final Map.Entry<String, Object> e : errorAttributes.entrySet()) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(e.getKey()).append("=").append(e.getValue());
      }
      log.info("Error: {}", sb.toString());
    }

    String messageCode = null;
    String additionalMessage = null;

    // First check if this is an exception received from the backend (UnrecoverableSignServiceException) ...
    //
    try {
      final HttpClientErrorException exception = this.getException(request, HttpClientErrorException.class);
      if (exception != null) {
        final ErrorBody errorBody = objectMapper.readValue(exception.getResponseBodyAsString(), ErrorBody.class);
        messageCode = errorBody.getErrorCode();
        additionalMessage = errorBody.getErrorMessage();
      }
    }
    catch (final Exception e) {
    }

    // Otherwise, display generic error
    //
    if (messageCode == null) {
      final HttpStatus status = this.getStatus(request);

      if (HttpStatus.NOT_FOUND.equals(status)) {
        messageCode = "error.unrecoverable.not-found";
      }
      else {
        messageCode = "error.unrecoverable.internal-error";
      }
    }

    final ModelAndView mav = new ModelAndView("error");
    mav.addObject("messageCode", messageCode);
    if (additionalMessage != null) {
      mav.addObject("message", additionalMessage);
    }

    return mav;
  }

  /**
   * Returns the exception from the error attributes.
   *
   * @param request the HTTP request
   * @param exceptionClass the exception class we are looking for
   * @return the exception or null
   */
  protected <T extends Exception> T getException(final HttpServletRequest request, final Class<T> exceptionClass) {
    Exception e = (Exception) request.getAttribute("javax.servlet.error.exception");
    while (e != null) {
      if (exceptionClass.isInstance(e)) {
        return exceptionClass.cast(e);
      }
      e = (Exception) e.getCause();
    }
    return null;
  }

  /**
   * A wrapping of Spring Boot's error structure used in REST error handling (with our extensions from the backend).
   */
  private static class ErrorBody extends HashMap<String, Object> {

    private static final long serialVersionUID = -6757349080763600026L;

    /**
     * Gets the {@code error-code} property.
     *
     * @return the error code or null
     */
    public String getErrorCode() {
      return (String) this.get("error-code");
    }

    /**
     * Gets the {@code error-message} property.
     *
     * @return the error message
     */
    public String getErrorMessage() {
      return Optional.ofNullable(this.get("error-message"))
          .map(String.class::cast)
          .orElseGet(() -> (String) this.get("message"));
    }

  }
}
