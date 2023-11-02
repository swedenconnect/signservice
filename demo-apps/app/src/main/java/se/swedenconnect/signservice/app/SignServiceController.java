/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.app;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.servletapi.ServletApiHttpUserRequest;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The SignService controller uses the SignServiceEngineManager to handle each request.
 */
@Controller
@Slf4j
public class SignServiceController {

  /** The session attribute name for storing the SignService context. */
  private static final String SIGNSERVICE_CONTEXT_NAME = SignServiceContext.class.getPackageName() + ".Context";

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

  @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws UnrecoverableSignServiceException {

    final HttpSession session = request.getSession();
    final SignServiceContext context = (SignServiceContext) session.getAttribute(SIGNSERVICE_CONTEXT_NAME);

    try {
      final SignServiceProcessingResult result =
          this.manager.processRequest(new ServletApiHttpUserRequest(request), context);

      // Update the SignService context ...
      //
      if (result.getSignServiceContext() == null) {
        session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
      }
      else {
        session.setAttribute(SIGNSERVICE_CONTEXT_NAME, result.getSignServiceContext());
      }

      // Should we write a response message back (HTTP status 200)?
      //
      if (result.getResponseAction().getBody() != null) {
        // Add response headers ...
        result.getResponseAction().getBody().getHeaders().forEach((n, v) -> response.addHeader(n, v));

        // Write response body ...
        try {
          response.getOutputStream().write(result.getResponseAction().getBody().getContents());
          response.flushBuffer();
          return null;
        }
        catch (final IOException e) {
          final String msg = String.format("Failed to write resource %s - %s", request.getRequestURI(), e.getMessage());
          log.info("{}", msg, e);
          throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.INTERNAL_ERROR, msg, e);
        }
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
    }
    catch (final UnrecoverableSignServiceException e) {
      // Clear the context ...
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
      throw e;
    }

    // Will never happen. The response action will always contain any of the three above options ...
    //
    throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.INTERNAL_ERROR, "Invalid backend response");
  }

}
