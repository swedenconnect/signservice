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
package se.swedenconnect.signservice.core.config;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.reflect.FieldUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * An abstract base class for {@link HandlerConfiguration} implementations that handles the base functionality for a
 * configuration object. Sub-classes should provide the actual configuration properties.
 */
public abstract class AbstractHandlerConfiguration<T extends SignServiceHandler> implements HandlerConfiguration<T> {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractHandlerConfiguration.class);

  /**
   * The class name of the factory class that should be used to create handlers based on this configuration.
   */
  private String factoryClass;

  /**
   * The handler name.
   */
  private String name;

  /**
   * In many cases, handlers of the same type share many configuration settings. Therefore, a default configuration may
   * be assigned to the configuration object. Any settings applied directly to the configuration object always overrides
   * the setting from the supplied default configuration.
   */
  private HandlerConfiguration<T> defaultConfig;

  /**
   * When configuration objects are created using Spring Boot's {@code ConfigurationProperties} paradigm, or perhaps
   * according another framework's way of handling configuration objects from properties files, we may not be able to
   * assign a created {@link HandlerConfiguration} object. Instead, the property file, that is the base for how the
   * configuration objects are created, can contain the {@code defaultConfigRef} property that points at a named
   * reference of a default configuration (that has been created earlier in the process).
   */
  private String defaultConfigRef;

  /**
   * A {@code beanName} of a handler bean may be assigned to the configuration object. This effectively cancels the
   * configuration, and the factory will not create a new handler object, instead it will just load the bean using the
   * supplied {@code beanName}.
   */
  private String beanName;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getFactoryClass() {
    return this.factoryClass != null ? this.factoryClass : this.getDefaultFactoryClass();
  }

  /** {@inheritDoc} */
  @Override
  public void setFactoryClass(@Nonnull final String factoryClass) {
    this.factoryClass = factoryClass;
  }

  /**
   * Gets the default factory class name to be used to create handlers based on this configuration.
   *
   * @return the factory class name
   */
  @Nonnull
  protected abstract String getDefaultFactoryClass();

  /** {@inheritDoc} */
  @Override
  public void init() throws Exception {
    if (this.factoryClass == null && this.getDefaultFactoryClass() == null) {
      throw new IllegalArgumentException("factoryClass can not be null");
    }
    if (this.defaultConfig != null) {
      this.mergeDefaultConfiguration(this.defaultConfig);
      this.defaultConfig = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setName(@Nonnull final String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Nullable
  @Override
  public String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public void setBeanName(@Nonnull final String beanName) {
    this.beanName = beanName;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getBeanName() {
    return this.beanName;
  }

  /** {@inheritDoc} */
  @Override
  public void setDefaultConfig(@Nonnull final HandlerConfiguration<T> defaultConfig) {
    if (defaultConfig != null && this.defaultConfigRef != null) {
      throw new IllegalArgumentException("Can not assign default-config, default-config-ref has already been assigned");
    }
    this.defaultConfig = defaultConfig;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<T> getDefaultConfig() {
    return this.defaultConfig;
  }

  /** {@inheritDoc} */
  @Override
  public void setDefaultConfigRef(@Nonnull final String defaultConfigRef) {
    if (defaultConfigRef != null && this.defaultConfig != null) {
      throw new IllegalArgumentException("Can not assign default-config-ref, default-config has already been assigned");
    }
    this.defaultConfigRef = defaultConfigRef;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getDefaultConfigRef() {
    return this.defaultConfigRef;
  }

  /** {@inheritDoc} */
  @Override
  public boolean needsDefaultConfigResolving() {
    return this.defaultConfigRef != null;
  }

  /** {@inheritDoc} */
  @Override
  public void resolveDefaultConfigRef(@Nonnull final Function<String, HandlerConfiguration<T>> resolver)
      throws NullPointerException, IllegalArgumentException {
    if (this.defaultConfigRef == null) {
      throw new IllegalArgumentException(
          "Invalid call to resolveDefaultConfigRef - no default-config-ref has been assigned");
    }
    final HandlerConfiguration<T> defaultConfig = resolver.apply(this.defaultConfigRef);
    if (defaultConfig == null) {
      throw new NullPointerException("Failed to resolve default-config-ref: " + this.defaultConfigRef);
    }
    this.mergeDefaultConfiguration(defaultConfig);
    this.defaultConfigRef = null;
  }

  /**
   * Merges the supplied default configuration into this object.
   * <p>
   * The default implementation uses reflection and merges all properties recursively into this object. See
   * {@link #mergeConfigObject(Object, Object)}.
   * </p>
   *
   * @param defaultConfiguration the default configuration to merge into this object.
   * @throws IllegalArgumentException if merging fails
   */
  protected void mergeDefaultConfiguration(@Nonnull final HandlerConfiguration<T> defaultConfiguration)
      throws IllegalArgumentException {
    this.mergeConfigObject(this, defaultConfiguration);
  }

  /**
   * When {@link #mergeConfigObject(Object, Object)} does its work, it recurses into all properties of the objects being
   * merged. By default it stops at primitive types and types from any {@code java.*} package. Otherwise it attempts to
   * list all getter methods from the default object and compare their values with the target object. This algorithm
   * covers most cases, but not all. It may be the case that some types that are properties of a configuration object
   * should be seen as 'atomic' and that we shouldn't recurse down into them. By providing these types by overriding
   * this method, the {@link #mergeConfigObject(Object, Object)} will not recurse into them.
   * <p>
   * The default implementation returns a list containing one element - {@code PkiCredential}.
   * </p>
   *
   * @return the classes to exclude from recursive merging
   */
  @Nonnull
  protected List<Class<?>> excludeFromRecursiveMerge() {
    return List.of(PkiCredential.class);
  }

  /**
   * Merges the default settings from {@code defaultObject} into {@code targetObject}. The method recurses and fills in
   * non-set properties in {@code targetObject} (or any of its child properties) with values from {@code defaultObject}
   * (or any of its child properties).
   *
   * @param targetObject the target object
   * @param defaultObject the object to get default properties from
   */
  protected void mergeConfigObject(@Nonnull final Object targetObject, @Nonnull final Object defaultObject)
      throws IllegalArgumentException {
    try {
      log.trace("Merging default configuration of type '{}' into target configuration object of type '{}' ...",
          defaultObject.getClass().getName(), targetObject.getClass().getName());

      // If the objects are equal, there is nothing to merge ...
      if (targetObject.equals(defaultObject)) {
        log.trace("Default configuration and target configuration are equal - no merging will be done");
        return;
      }

      if (List.class.isAssignableFrom(targetObject.getClass())) {
        this.mergeLists(targetObject, defaultObject);
        return;
      }
      if (targetObject.getClass().isArray()) {
        this.mergeArrays(targetObject, defaultObject);
        return;
      }
      if (Map.class.isAssignableFrom(targetObject.getClass())) {
        this.mergeMaps(targetObject, defaultObject);
        return;
      }

      // If this object is a non-complex class (for example a String) we shouldn't merge
      // since 'thisObject' already has a value.
      if (targetObject.getClass().getPackageName().startsWith("java.")) {
        log.trace("Since the objects are of type '{}' no merge will be attempted", targetObject.getClass().getName());
        return;
      }

      // Else, list att getters of the default object and compare against our object ...
      //
      log.trace("Listing all getter methods from default configuration object ...");
      for (final Method method : defaultObject.getClass().getMethods()) {
        if (!this.isMergeCandidate(method)) {
          continue;
        }
        log.trace("Checking whether value of '{}' should be merged ...", method.getName());

        // Get the value for the default object getter ...
        final Object mergeValue = method.invoke(defaultObject);
        if (mergeValue == null) {
          log.trace("Execution of {} on default configuration object returned null - will not be merged",
              method.getName());
          continue;
        }
        // Get the value from the target object ...
        final Method targetMethod = targetObject.getClass().getMethod(method.getName());
        Object targetValue = targetMethod.invoke(targetObject);
        if (targetValue == null) {
          log.trace("Execution of {} on target configuration object return null - merging value from default",
              method.getName());
          this.assignValue(targetObject, getterNameToSetter(targetMethod.getName()), method.getReturnType(),
              mergeValue);
        }
        else {
          // Before we go on and make a recursive call, we check if these types are excluded from merging.
          //
          for (final Class<?> clazz : this.excludeFromRecursiveMerge()) {
            if (clazz.isAssignableFrom(targetValue.getClass())) {
              log.trace("{} is excluded from merge - will not recurse", targetValue.getClass().getName());
              continue;
            }
          }
          // If targetValue is an array, we need to make sure that its size is equal to mergeValue's.
          // Otherwise merging of the array will not be possible ...
          //
          if (targetValue.getClass().isArray()) {
            if (Array.getLength(mergeValue) > Array.getLength(targetValue)) {
              final Object updatedTargetValue =
                  Array.newInstance(targetValue.getClass().getComponentType(), Array.getLength(mergeValue));
              for (int i = 0; i < Array.getLength(targetValue); i++) {
                Array.set(updatedTargetValue, i, Array.get(targetValue, i));
              }
              targetValue = updatedTargetValue;
              this.assignValue(targetObject, getterNameToSetter(targetMethod.getName()), method.getReturnType(),
                  targetValue);
            }
          }

          this.mergeConfigObject(targetValue, mergeValue);
        }
      }
    }
    catch (final ReflectiveOperationException e) {
      final String msg = "Failed to merge default configuration";
      log.info("{}", msg, e);
      throw new IllegalArgumentException(msg, e);
    }
  }

  /**
   * Merges two lists.
   *
   * @param targetObject the target
   * @param defaultObject the source (default settings)
   */
  protected void mergeLists(@Nonnull final Object targetObject, @Nonnull final Object defaultObject) {
    @SuppressWarnings({ "unchecked", "rawtypes" })
    final List<Object> targetList = (List) targetObject;
    @SuppressWarnings({ "unchecked", "rawtypes" })
    final List<Object> defaultList = (List) defaultObject;

    final int tSize = targetList.size();

    if (defaultList.size() > tSize) {
      for (int i = tSize; i < defaultList.size(); i++) {
        try {
          targetList.add(defaultList.get(i));
        }
        catch (final UnsupportedOperationException e) {
          log.warn("Could not merge config lists - static array list is being used");
        }
      }
    }
    for (int i = 0; i < tSize; i++) {
      if (defaultList.size() - 1 < i) {
        break;
      }
      final Object tObj = targetList.get(i);
      final Object dObj = defaultList.get(i);
      this.mergeConfigObject(tObj, dObj);
      targetList.set(i, tObj);
    }
  }

  /**
   * Merges two arrays. When called we know that the size of the targetObject array is no less than defaultObject.
   *
   * @param targetObject the target
   * @param defaultObject the source (default settings)
   */
  protected void mergeArrays(@Nonnull final Object targetObject, @Nonnull final Object defaultObject) {

    for (int i = 0; i < Array.getLength(targetObject); i++) {
      if (Array.getLength(defaultObject) < i) {
        break;
      }
      final Object dObj = Array.get(defaultObject, i);
      if (dObj == null) {
        continue;
      }
      final Object tObj = Array.get(targetObject, i);
      if (tObj == null) {
        Array.set(targetObject, i, dObj);
      }
      else {
        this.mergeConfigObject(tObj, dObj);
        Array.set(targetObject, i, tObj);
      }
    }
  }

  /**
   * Merges two maps.
   *
   * @param targetObject the target
   * @param defaultObject the source (default settings)
   */
  protected void mergeMaps(@Nonnull final Object targetObject, @Nonnull final Object defaultObject) {
    @SuppressWarnings("unchecked")
    final Map<Object, Object> targetMap = (Map<Object, Object>) targetObject;
    @SuppressWarnings("unchecked")
    final Map<Object, Object> defaultMap = (Map<Object, Object>) defaultObject;

    for (final Object dkey : defaultMap.keySet()) {
      final Object tValue = targetMap.get(dkey);
      final Object dValue = defaultMap.get(dkey);
      if (tValue == null) {
        targetMap.put(dkey, dValue);
      }
      else if (dValue != null) {
        this.mergeConfigObject(tValue, dValue);
        targetMap.put(dkey, tValue);
      }
    }
  }

  /**
   * Predicate that tells whether the supplied method is a candidate for merging.
   * <p>
   * Only no-parameter methods prefixed with {@code get} and {@code is} (with boolean return values) are candidates.
   * </p>
   *
   * @param method the method to test
   * @return true if the method is a candidate for merging and false otherwise
   */
  protected boolean isMergeCandidate(@Nonnull final Method method) {
    if (method.getParameterCount() > 0) {
      return false;
    }
    final String methodName = method.getName();
    final Class<?> returnType = method.getReturnType();

    if ("getClass".equals(methodName) || "getDefaultConfig".equals(methodName)
        || "getDefaultConfigRef".equals(methodName)) {
      return false;
    }
    return methodName.startsWith("get") ||
        (methodName.startsWith("is")
            && (returnType.isAssignableFrom(Boolean.class) || returnType.isAssignableFrom(boolean.class)));
  }

  /**
   * Assigns the value from the default config object to our target object. This is done when the target object did not
   * have a value assigned.
   *
   * @param targetObject the object to update
   * @param setter the setter method to use
   * @param parameterType the type of the parameter to assign
   * @param value the value to assign
   * @throws ReflectiveOperationException for reflection errors
   */
  protected void assignValue(@Nonnull final Object targetObject, @Nonnull final String setter,
      @Nonnull final Class<?> parameterType, @Nonnull final Object value) throws ReflectiveOperationException {
    try {
      log.trace("Loading method {} on {} ...", setter, targetObject.getClass().getName());
      final Method setterMethod = targetObject.getClass().getMethod(setter, parameterType);
      log.trace("Invoking {} on target object of type {}", setter, targetObject.getClass().getName());
      setterMethod.invoke(targetObject, value);
      log.trace("{} successfully executed on target object", setter);
    }
    catch (final NoSuchMethodException e) {
      final String fieldName = setterNameToField(setter);
      log.trace("{} was not available on target object {} - trying to assign {} directly...",
          setter, targetObject.getClass().getName(), fieldName);
      final Field field = FieldUtils.getField(targetObject.getClass(), fieldName, true);
      if (field == null) {
        // Don't treat this as an error. If there is no setter and no field matching, we just
        // won't merge ...
        log.trace("Target object has no setter and no field {}, value is not merged", fieldName);
        return;
      }
      FieldUtils.writeField(field, targetObject, value, true);
      log.trace("Field '{}' on {} was updated with value from default config object",
          fieldName, targetObject.getClass().getName());
    }
  }

  /**
   * Given the name for the getter method, the method returns the corresponding setter method name.
   *
   * @param getter the getter method name
   * @return the setter method name
   */
  protected static String getterNameToSetter(@Nonnull final String getter) {
    if (getter.startsWith("get")) {
      return getter.replaceFirst("get", "set");
    }
    else if (getter.startsWith("is")) {
      return getter.replaceFirst("is", "set");
    }
    else {
      throw new IllegalArgumentException("Invalid getter method name");
    }
  }

  /**
   * Given the name for the setter method, this method returns the corresponding field name.
   *
   * @param setter the setter method name
   * @return the corresponding field name (member variable)
   */
  protected static String setterNameToField(@Nonnull final String setter) {
    final String field = setter.substring(3);
    return field.substring(0, 1).toLowerCase() + field.substring(1);
  }

}
