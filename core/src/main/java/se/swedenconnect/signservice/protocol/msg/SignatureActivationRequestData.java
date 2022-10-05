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
package se.swedenconnect.signservice.protocol.msg;

import java.io.Serializable;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * If the signature request is for a qualified certificate associated with a private key held in a Qualified Signature
 * Creation Device according to eIDAS the signature service must request by the identity provider a proof for this. This
 * interface describes the parameters needed to include in such a request.
 */
public interface SignatureActivationRequestData extends Serializable {

  /**
   * The same as {@link SignRequestMessage#getRequestId()}.
   *
   * @return the sign request ID
   */
  @Nonnull
  String getSignRequestId();

  /**
   * Gets the number of documents that are to be signed. This information is part of the Signature Activation Data.
   * @return the document count
   */
  int getDocumentCount();

  /**
   * A predicate that tells whether it is mandatory to pass a "Signature Activation Data" request to the identity
   * provider.
   *
   * @return if true the SAD request is mandatory
   */
  boolean isRequired();

}
