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
package se.swedenconnect.signservice.protocol.dss;

import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;

/**
 * {@link ProtocolProcessingRequirements} for the implementation according to <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 */
class DssProtocolProcessingRequirements implements ProtocolProcessingRequirements {

  /** For serializing. */
  private static final long serialVersionUID = -3320941124228836728L;

  /** {@inheritDoc} */
  @Override
  public SignatureRequirement getRequestSignatureRequirement() {
    return SignatureRequirement.REQUIRED;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureRequirement getResponseSignatureRequirement() {
    return SignatureRequirement.REQUIRED;
  }

  /** {@inheritDoc} */
  @Override
  public String getResponseSendMethod() {
    return "POST";
  }

}
