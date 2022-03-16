/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.protocol.impl;

import javax.annotation.PostConstruct;
import org.apache.commons.lang.StringUtils;
import se.swedenconnect.signservice.api.protocol.SignServiceProtocolProfile;

/**
 * Default implementation of the {@link SignServiceProtocolProfile} interface.
 */
public class DefaultSignServiceProtocolProfile implements SignServiceProtocolProfile {

  /** For serializing. */
  private static final long serialVersionUID = -258114909954900341L;

  /** The profile name. */
  private String name;

  /** The requests signature requirement. */
  private SignatureRequirement requestSignatureRequirement;

  /**
   * Default constructor.
   */
  public DefaultSignServiceProtocolProfile() {}

  /**
   * Asserts that all required properties have been set.
   *
   * @throws Exception if the object has not been initialized correctly
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (StringUtils.isBlank(this.name)) {
      throw new IllegalArgumentException("Property 'name' must be set");
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

  /**
   * Sets the name of the SignService protocol profile.
   *
   * @param name the profile name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureRequirement getRequestSignatureRequirement() {
    return this.requestSignatureRequirement;
  }

  @Override
  public SignatureRequirement getResponseSignatureRequirement() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getResponseSendMethod() {
    // TODO Auto-generated method stub
    return null;
  }

}
