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

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import lombok.Setter;
import se.swedenconnect.signservice.application.rest.RestProcessRequestInput;
import se.swedenconnect.signservice.application.rest.RestProcessRequestResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.servletapi.ServletApiHttpUserRequest;

/**
 * The SignService frontend controller invokes the backend for each request.
 */
@Controller
public class SignServiceFrontendController {

  /** The session attribute name for storing the encoded SignService context. */
  private static final String SIGNSERVICE_CONTEXT_NAME = SignServiceContext.class.getPackageName() + ".Context";

  /**
   * The REST template that we use to communicate with the backend.
   */
  @Autowired
  @Setter
  private RestTemplate restTemplate;

  /**
   * The frontend configuration.
   */
  @Autowired
  @Setter
  private SignServiceFrontendConfigurationProperties config;

  /**
   * The entry point for requests to the SignService application.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @return a ModelAndView or null (in cases where we write to the response)
   * @throws IOException for processing errors
   * @throws RestClientException for errors received from the backend
   */
  @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, RestClientException {

    // Pick up the context session attribute.
    //
    final HttpSession session = request.getSession();
    final String context = (String) session.getAttribute(SIGNSERVICE_CONTEXT_NAME);

    // Invoke the backend ...
    // We pass the context (which may be null) and a mapping of the incoming request.
    //
    final RestProcessRequestResult result;
    try {
      result = this.restTemplate.postForObject(
          this.config.getBackendUrl() + this.config.getProcessPath(),
          new RestProcessRequestInput(context, new ServletApiHttpUserRequest(request)),
          RestProcessRequestResult.class);
    }
    catch (final RestClientException e) {
      // If we got an error, we remove the context from the session ...
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
      throw e;
    }

    // OK, we have a result. First update the SignService context ...
    //
    if (result.getContext() == null) {
      // If no context was passed back it means that we are done and the session should be cleared.
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
    }
    else {
      // Otherwise, we update the context. More requests within the same signature
      // operation will come.
      session.setAttribute(SIGNSERVICE_CONTEXT_NAME, result.getContext());
    }

    // Should we write a response message back (HTTP status 200)?
    //
    if (result.getResponseAction().getBody() != null) {
      // Add response headers ...
      result.getResponseAction().getBody().getHeaders().forEach((n, v) -> response.addHeader(n, v));

      // Write response body ...
      response.getOutputStream().write(result.getResponseAction().getBody().getContents());
      response.flushBuffer();
      return null;
    }

    // Redirect the user?
    //
    if (result.getResponseAction().getRedirect() != null) {
      return new ModelAndView("redirect:" + result.getResponseAction().getRedirect().getUrl());
    }

    // POST the user?
    //
    if (result.getResponseAction().getPost() != null) {
      final ModelAndView mav = new ModelAndView("post");
      mav.addObject("action", result.getResponseAction().getPost().getUrl());
      mav.addObject("parameters", result.getResponseAction().getPost().getParameters());
      return mav;
    }

    // Will never happen. The response action will always contain any of the three above options ...
    //
    throw new IOException("Invalid backend response");
  }

}
