/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.config.spring.converters;

import org.springframework.core.convert.converter.Converter;

import jakarta.annotation.Nonnull;
import se.swedenconnect.opensaml.common.utils.LocalizedString;

/**
 * Converts from a string to a localized string.
 */
public class LocalizedStringConverter implements Converter<String, LocalizedString> {

  /**
   * Converts strings on the format {@code <lang-tag>-<string according to language>}. The string "en-Hello" will give a
   * LocalizedString where:
   *
   * <pre>{@code
   * ls.getLanguage() => "en"
   * ls.getLocalString() => "Hello"}
   * </pre>
   */
  @Override
  public LocalizedString convert(@Nonnull final String source) {
    return new LocalizedString(source);
  }

}

