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
package se.swedenconnect.signservice.app.backend;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.Setter;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.application.rest.RestProcessRequestInput;
import se.swedenconnect.signservice.application.rest.RestProcessRequestResult;
import se.swedenconnect.signservice.context.DefaultSignServiceContext;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The backend controller is a REST-version of the {@link SignServiceEngineManager}.
 */
@RestController
public class SignServiceBackendController {

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

  /**
   * Receives a request containing the user request and invokes the {@link SignServiceEngineManager}.
   *
   * @param input the context and user request
   * @return a RestProcessRequestResult which is a wrapper around SignServiceProcessingResult
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   */
  @PostMapping(path = "/process", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public RestProcessRequestResult processRequest(@RequestBody final RestProcessRequestInput input)
      throws UnrecoverableSignServiceException {

    final SignServiceContext context = Optional.ofNullable(input.getContext())
        .map(c -> DefaultSignServiceContext.deserialize(c))
        .orElse(null);

    final SignServiceProcessingResult result =
        this.manager.processRequest(input.getUserRequest(), context);

    return new RestProcessRequestResult(result);
  }

}
