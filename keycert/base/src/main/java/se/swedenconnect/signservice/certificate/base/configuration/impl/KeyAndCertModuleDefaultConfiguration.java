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

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Implementation of default configuration data for the Key and Cert module
 * <p>
 * Consider moving this implementation to a generic module to be used also by other modules
 */
@Slf4j
public class KeyAndCertModuleDefaultConfiguration implements DefaultConfiguration {

  private final Map<String, Object> genericConfigMap;
  private final Map<String, Map<String, Object>> clientSpecificConfigMap;

  /**
   * Constructor that instantiates a new configuration registry;
   */
  public KeyAndCertModuleDefaultConfiguration() {
    genericConfigMap = new HashMap<>();
    clientSpecificConfigMap = new HashMap<>();
  }

  /**
   * Stores a default value for a named parameter that is valid across all requesting services
   *
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   */
  @Override public <T extends Serializable> void put(final @NonNull String parameterName,
    final @NonNull T defaultValue) {
    put(parameterName, defaultValue, null);
  }

  /**
   * Stores a default value for a named parameter that is valid specific clientId
   *
   * @param parameterName the unique name of the parameter
   * @param defaultValue the element to store
   * @param clientId the clientId for the requester for which this default value is set
   */
  @Override public <T extends Serializable> void put(final @NonNull String parameterName, final @NonNull T defaultValue,
    final String clientId) {

    if (StringUtils.isBlank(clientId)) {
      genericConfigMap.put(parameterName, defaultValue);
      return;
    }
    if (clientSpecificConfigMap.containsKey(clientId)) {
      clientSpecificConfigMap.get(clientId).put(parameterName, defaultValue);
    }
    else {
      Map<String, Object> clientSpecificMap = new HashMap<>();
      clientSpecificMap.put(parameterName, defaultValue);
      clientSpecificConfigMap.put(clientId, clientSpecificMap);
    }
  }

  /**
   * Gets a default value.
   *
   * @param parameterName the unique name of the parameter
   * @param clientId optional clientId or null to just get default values that are valid for any clientId
   * @return the default value, or null if no matching default value is available
   */
  @Override public Object get(final @NonNull String parameterName, final String clientId) {
    Object genericValue = genericConfigMap.get(parameterName);
    if (StringUtils.isBlank(clientId)) {
      return genericValue;
    }
    Object specificValue = null;
    if (clientSpecificConfigMap.containsKey(clientId)) {
      specificValue = clientSpecificConfigMap.get(clientId).get(parameterName);
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
  @Override public <T extends Serializable> T get(String parameterName, String clientId,
    Class<T> type) throws ClassCastException {
    return Optional.ofNullable(get(parameterName, clientId)).map(type::cast).orElse(null);
  }
}
