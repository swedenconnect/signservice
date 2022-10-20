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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.Setter;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngineManager;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The SignService controller uses the SignServiceEngineManager to handle each request.
 */
@Controller
public class SignServiceController {

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

  @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws UnrecoverableSignServiceException {

    final HttpRequestMessage result = this.manager.processRequest(request, response);

    if (result == null) {
      return null;
    }
    else {
      if ("GET".equals(result.getMethod())) {
        return new ModelAndView("redirect:" + result.getUrl());
      }
      else { // POST
        final ModelAndView mav = new ModelAndView("post");
        mav.addObject("action", result.getUrl());
        mav.addObject("parameters", result.getHttpParameters());
        return mav;
      }
    }
  }

}
