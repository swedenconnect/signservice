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
package se.swedenconnect.signservice.certificate.base.configuration.impl;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang.StringUtils;

import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;

/**
 * Implementation of default configuration data for the Key and Cert module.
 * <p>
 * Consider moving this implementation to a generic module to be used also by other modules.
 */
public class KeyAndCertModuleDefaultConfiguration implements DefaultConfiguration {

  private final Map<String, Object> genericConfigMap;
  private final Map<String, Map<String, Object>> clientSpecificConfigMap;

  /**
   * Constructor that instantiates a new configuration registry;
   */
  public KeyAndCertModuleDefaultConfiguration() {
    this.genericConfigMap = new HashMap<>();
    this.clientSpecificConfigMap = new HashMap<>();
  }

  /**
   * Stores a default value for a named parameter that is valid across all requesting services
   *
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   */
  @Override
  public <T extends Serializable> void put(final String parameterName, final T defaultValue) {
    this.put(parameterName, defaultValue, null);
  }

  /**
   * Stores a default value for a named parameter that is valid specific clientId
   *
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   * @param clientId the clientId for the requester for which this default value is set
   */
  @Override
  public <T extends Serializable> void put(final String parameterName, final T defaultValue, final String clientId) {

    Objects.requireNonNull(parameterName, "parameterName must not be null");
    Objects.requireNonNull(defaultValue, "defaultValue must not be null");

    if (StringUtils.isBlank(clientId)) {
      this.genericConfigMap.put(parameterName, defaultValue);
      return;
    }
    if (this.clientSpecificConfigMap.containsKey(clientId)) {
      this.clientSpecificConfigMap.get(clientId).put(parameterName, defaultValue);
    }
    else {
      final Map<String, Object> clientSpecificMap = new HashMap<>();
      clientSpecificMap.put(parameterName, defaultValue);
      this.clientSpecificConfigMap.put(clientId, clientSpecificMap);
    }
  }

  /**
   * Gets a default value.
   *
   * @param parameterName the unique name of the parameter
   * @param clientId optional clientId or null to just get default values that are valid for any clientId
   * @return the default value, or null if no matching default value is available
   */
  @Override
  public Object get(final String parameterName, final String clientId) {
    final Object genericValue = this.genericConfigMap.get(Objects.requireNonNull(parameterName, "parameterName must not be null"));
    if (StringUtils.isBlank(clientId)) {
      return genericValue;
    }
    Object specificValue = null;
    if (this.clientSpecificConfigMap.containsKey(clientId)) {
      specificValue = this.clientSpecificConfigMap.get(clientId).get(parameterName);
    }
    return specificValue != null
        ? specificValue
        : genericValue;
  }

  /**
   * Gets a named data element having a given type from the context.
   *
   * @param parameterName the unique name of the parameter
   * @param clientId optional clientId or null to just get default values that are valid for any clientId
   * @param type the type of the parameter value
   * @return the default value, or null if no matching default value is available
   * @throws ClassCastException if the default value exists but is not of the given type
   */
  @Override
  public <T extends Serializable> T get(final String parameterName, final String clientId,
      final Class<T> type) throws ClassCastException {
    return Optional.ofNullable(this.get(parameterName, clientId)).map(type::cast).orElse(null);
  }
}
