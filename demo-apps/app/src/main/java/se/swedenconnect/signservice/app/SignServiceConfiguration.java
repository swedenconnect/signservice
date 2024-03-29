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
package se.swedenconnect.signservice.app;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Configuration for SignService.
 */
@Configuration
public class SignServiceConfiguration {

  /**
   * Gets a {@link ReplayCheckerStorageContainer} bean. For production cases where several application instances are
   * used an in-memory variant should not be used.
   *
   * @return a ReplayCheckerStorageContainer bean
   */
  @Bean
  InMemoryReplayCheckerStorageContainer inMemoryReplayCheckerStorageContainer() {
    return new InMemoryReplayCheckerStorageContainer("replay-storage");
  }

}
