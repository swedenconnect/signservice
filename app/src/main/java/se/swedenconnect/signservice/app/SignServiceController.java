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
package se.swedenconnect.signservice.app;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.Setter;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The SignService controller uses the SignServiceEngineManager to handle each request.
 */
@Controller
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

    final SignServiceProcessingResult result = this.manager.processRequest(request, response, context);

    // Update the SignService context ...
    //
    if (result.getSignServiceContext() == null) {
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
    }
    else {
      session.setAttribute(SIGNSERVICE_CONTEXT_NAME, result.getSignServiceContext());
    }

    final HttpRequestMessage http = result.getHttpRequestMessage();
    if (http == null) {
      return null;
    }
    else {
      if ("GET".equals(http.getMethod())) {
        return new ModelAndView("redirect:" + http.getUrl());
      }
      else { // POST
        final ModelAndView mav = new ModelAndView("post");
        mav.addObject("action", http.getUrl());
        mav.addObject("parameters", http.getHttpParameters());
        return mav;
      }
    }
  }

}
