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
package se.swedenconnect.signservice.app.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * SignService application backend main.
 */
@SpringBootApplication
@EnableScheduling
public class SignServiceBackend {

  /**
   * Program main.
   *
   * @param args program arguments
   */
  public static void main(final String[] args) {
    SpringApplication.run(SignServiceBackend.class, args);
  }

  /**
   * A simple container bean for replay checking.
   * <p>
   * Note: For production purposes an in-memory solution should be avoided if more than one instance is used.
   * </p>
   *
   * @return a ReplayCheckerStorageContainer
   */
  @Bean
  public ReplayCheckerStorageContainer inMemoryReplayCheckerStorageContainer() {
    return new InMemoryReplayCheckerStorageContainer("replay-storage");
  }

}
