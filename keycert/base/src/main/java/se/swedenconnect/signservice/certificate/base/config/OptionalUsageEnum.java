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

package se.swedenconnect.signservice.certificate.base.config;

/**
 * Optional usage settings for signing keys.
 *
 * <p>All signing keys are marked for usage with signing operations and by default
 * will be marked for non-repudiation. These enumerations allow optional key usage settings</p>
 */
public enum OptionalUsageEnum {
  /** The key is allowed to be used to encrypt data */
  encrypt,
  /** The key */
  excludeNr
  /** The key is not marked for non-repudiation */
}
