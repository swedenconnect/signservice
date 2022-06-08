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

package se.swedenconnect.signservice.signature.tbsdata.impl;

import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessorProvider;

/**
 * Default provider of a suitable processor to prepare data to be signed
 */
public class DefaultTBSDataProcessorProvider implements TBSDataProcessorProvider {

  @Override public TBSDataProcessor getTBSDataProcessor(SignatureAlgorithm signatureAlgorithm) {
    return null;
  }
}
