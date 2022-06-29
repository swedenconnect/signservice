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

import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;

import javax.annotation.Nonnull;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * Interface for a "To Be Signed" data processor that prepares data for signing based on a specific signature format.
 */
public interface TBSDataProcessor {

  /**
   * Process the sign task data to obtain the data To Be Signed
   *
   * @param signatureTask requested signature task data
   * @param signerCertificate the certificate of the intended signer
   * @param signatureAlgorithm Signature algorithm
   * @return the data to be signed
   * @throws SignatureException on errors providing data to be signed based on the provided input
   */
  TBSProcessingData processSignTaskData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final X509Certificate signerCertificate, @Nonnull final SignatureAlgorithm signatureAlgorithm)
    throws SignatureException;

  /**
   * Check an instance of requested signature task data against the specified signature algorithm
   *
   * @param signatureTask requested signature task data
   * @param signatureAlgorithm signature algorithm
   * @throws InvalidRequestException if the provided data is not valid
   */
  void checkSignTask(final RequestedSignatureTask signatureTask, final SignatureAlgorithm signatureAlgorithm)
    throws InvalidRequestException;
}
