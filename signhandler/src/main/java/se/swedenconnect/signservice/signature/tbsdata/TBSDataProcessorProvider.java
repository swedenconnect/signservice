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
package se.swedenconnect.signservice.signature.tbsdata;

import se.swedenconnect.signservice.signature.SignatureType;

import javax.annotation.Nonnull;
import java.security.SignatureException;

/**
 * Interface for a provider of to be signed data processors
 */
public interface TBSDataProcessorProvider {

  /**
   * Get a suitable to be signed data processor for the specified signature type
   *
   * @param signatureType signature type such as XML or PDF
   * @return {@link TBSDataProcessor}
   * @throws SignatureException on errors creating the TBS data processor
   */
  TBSDataProcessor getTBSDataProcessor(@Nonnull final SignatureType signatureType)  throws SignatureException;
}
