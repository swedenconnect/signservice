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
package se.swedenconnect.signservice.storage.impl;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * Test cases for DefaultMessageReplayChecker.
 */
public class DefaultMessageReplayCheckerTest {

  @Test
  public void testReplayChecker() throws Exception {
    final DefaultMessageReplayChecker checker = new DefaultMessageReplayChecker(new InMemoryReplayCheckerStorageContainer("store"));
    checker.checkReplay("id1");
    assertThatThrownBy(() -> {
      checker.checkReplay("id1");
    }).isInstanceOf(MessageReplayException.class)
      .hasMessage("Replay check of ID 'id1' failed");
  }

}
