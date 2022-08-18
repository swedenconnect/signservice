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
package se.swedenconnect.signservice.audit.file;

import java.util.Optional;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;

import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Handler configuration for creating {@link FileAuditLogger} instances.
 */
public class FileAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /** The audit log file name (including its full path). */
  private String fileName;

  /**
   * Gets the audit log file name (including its full path).
   *
   * @return the audit log file name
   */
  @Nonnull
  public String getFileName() {
    return this.fileName;
  }

  /**
   * Assigns the audit log file name (including its full path).
   *
   * @param fileName the audit log file name
   */
  public void setFileName(@Nonnull final String fileName) {
    this.fileName = Optional.ofNullable(fileName)
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new NullPointerException("fileName must not be null or empty"));
  }

  /** {@inheritDoc} */
  @Override
  protected String getDefaultFactoryClass() {
    return FileAuditLoggerFactory.class.getName();
  }

}
