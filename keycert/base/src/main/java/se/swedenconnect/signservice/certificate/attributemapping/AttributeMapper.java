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
package se.swedenconnect.signservice.certificate.attributemapping;

import java.util.List;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Attribute mapper interface.
 */
public interface AttributeMapper {

  /**
   * Get certificate mapping data from authentication result and sign request.
   *
   * @param signRequest sign request
   * @param assertion assertion data
   * @return certificate attribute mappings
   * @throws AttributeMappingException error processing attribute mapping data
   */
  @Nonnull
  List<AttributeMappingData> mapCertificateAttributes(@Nonnull SignRequestMessage signRequest,
    @Nonnull IdentityAssertion assertion) throws AttributeMappingException;

}
