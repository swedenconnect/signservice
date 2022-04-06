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

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The SignService controller that dispatches the requests to the different engines.
 */
@Controller
@Slf4j
public class SignServiceController {

  @Autowired
  @Qualifier("signservice.Engines")
  public List<SignServiceEngine> engines;

  @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, UnrecoverableSignServiceException {

    log.debug("Received {} request [path: '{}', client-ip: '{}']",
        request.getMethod(), request.getRequestURI(), request.getRemoteAddr());

    // Find an engine that can process the request ...
    //
    final SignServiceEngine engine = this.dispatch(request);
    if (engine == null) {
      log.info("No SignServiceEngine can service {} request on {}", request.getMethod(), request.getRequestURI());
      throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.NOT_FOUND, "No such resource");
    }

    // Hand the request over to the engine ...
    //
    final HttpRequestMessage result = engine.processRequest(request, response);

    if (result == null) {
      // If the result from the processing is null, it means that the engine, or any of its
      // sub-components, has served a resource and written it to the HttpServletResponse. All we
      // have to do now is commit the response ...
      //
      log.debug("Engine has served resource, flushing buffer ...");
      response.flushBuffer();
      return null;
    }
    else {
      if ("GET".equals(result.getMethod())) {
        // We should send a redirect ...
        //
        log.debug("Redirecting to: {}", result.getUrl());
        return new ModelAndView("redirect:" + result.getUrl());
      }
      else { // POST
        ModelAndView mav = new ModelAndView("post");
        mav.addObject("action", result.getUrl());
        mav.addObject("parameters", result.getHttpParameters());
        return mav;
      }
    }
  }

  private SignServiceEngine dispatch(final HttpServletRequest request) {
    for (final var e : this.engines) {
      if (e.canProcess(request)) {
        return e;
      }
    }
    return null;
  }

}
