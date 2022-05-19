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
package se.swedenconnect.signservice.certificate.base.configuration;

import java.io.Serializable;

/**
 * This is a temporary design of an interface for storing and retrieving configured default values for various
 * protocol parameters. The naming of parameters is outside the scope of this interface
 * <p>
 * This interface should be moved to a common area of this project
 */
public interface DefaultConfiguration {

  /**
   * Stores a default value for a named parameter that is valid across all requesting services
   *
   * @param <T> the type of the default parameter value
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   */
  <T extends Serializable> void put(final String parameterName, final T defaultValue);

  /**
   * Stores a default value for a named parameter that is valid specific clientId
   *
   * @param <T> the type of the default parameter value
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   * @param clientId the clientId for the requester for which this default value is set
   */
  <T extends Serializable> void put(final String parameterName, final T defaultValue, String clientId);

  /**
   * Gets a default value.
   *
   * @param parameterName the unique name of the parameter
   * @param clientId optional clientId or null to just get default values that are valid for any clientId
   * @return the default value, or null if no matching default value is available
   */
  Object get(final String parameterName, final String clientId);

  /**
   * Gets a named data element having a given type from the context.
   *
   * @param <T> the type of the parameter value
   * @param parameterName the unique name of the parameter
   * @param clientId optional clientId or null to just get default values that are valid for any clientId
   * @param type the type of the parameter value
   * @return the default value, or null if no matching default value is available
   * @throws ClassCastException if the default value exists but is not of the given type
   */
  <T extends Serializable> T get(final String parameterName, final String clientId, final Class<T> type)
    throws ClassCastException;

}
