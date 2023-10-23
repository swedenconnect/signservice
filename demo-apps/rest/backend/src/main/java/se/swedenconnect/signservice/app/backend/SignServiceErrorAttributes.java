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

import java.util.Map;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * Customization of the attributes sent back in error responses.
 */
@Component
public class SignServiceErrorAttributes extends DefaultErrorAttributes {

  /** {@inheritDoc} */
  @Override
  public Map<String, Object> getErrorAttributes(final WebRequest webRequest, final ErrorAttributeOptions options) {

    final Map<String, Object> errorAttributes = super.getErrorAttributes(webRequest, options);

    if (this.getError(webRequest) instanceof UnrecoverableSignServiceException) {
      final UnrecoverableSignServiceException error = UnrecoverableSignServiceException.class.cast(this.getError(webRequest));

      errorAttributes.put("error-code", error.getErrorCode());
      errorAttributes.put("error-message", error.getMessage());
    }

    return errorAttributes;
  }

}
