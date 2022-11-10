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
package se.swedenconnect.signservice.engine.session;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Test cases for EngineContext.
 */
public class EngineContextTest {

  @Test
  public void testCtorNullArg() {
    assertThatThrownBy(() -> {
      new EngineContext(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("context must not be null");
  }

  @Test
  public void testCreateSignServiceContext() {
    final SignServiceContext ssc = EngineContext.createSignServiceContext();
    Assertions.assertNotNull(ssc.getId());
    final EngineContext context = new EngineContext(ssc);
    Assertions.assertEquals(SignOperationState.NEW, context.getState());
    Assertions.assertEquals(ssc.getId(), context.getId());
    Assertions.assertEquals(ssc, context.getContext());
  }

  @Test
  public void testMissingState() {
    final SignServiceContext ssc = EngineContext.createSignServiceContext();
    Assertions.assertNotNull(ssc.getId());
    final EngineContext context = new EngineContext(ssc);
    ssc.remove(EngineContext.class.getPackageName() + ".State");

    assertThatThrownBy(() -> {
      context.getState();
    }).isInstanceOf(IllegalStateException.class)
        .hasMessage("No SignService state available");
  }

  @Test
  public void testUpdateState() {
    final EngineContext context = new EngineContext(EngineContext.createSignServiceContext());

    assertThatThrownBy(() -> {
      context.updateState(SignOperationState.NEW);
    }).isInstanceOf(IllegalStateException.class)
        .hasMessage("Illegal state transition - Cannot set state to NEW");

    assertThatThrownBy(() -> {
      context.updateState(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("Supplied state must not be null");

    context.updateState(SignOperationState.AUTHN_ONGOING);
    Assertions.assertEquals(SignOperationState.AUTHN_ONGOING, context.getState());

    context.updateState(SignOperationState.SIGNING);
    Assertions.assertEquals(SignOperationState.SIGNING, context.getState());

    context.updateState(SignOperationState.SIGNING);
    Assertions.assertEquals(SignOperationState.SIGNING, context.getState());

    assertThatThrownBy(() -> {
      context.updateState(SignOperationState.AUTHN_ONGOING);
    }).isInstanceOf(IllegalStateException.class)
        .hasMessage("Illegal state transition - Cannot go backwards in state transitions");
  }

  @Test
  public void testPutAndGet() {
    final EngineContext context = new EngineContext(EngineContext.createSignServiceContext());

    assertThatThrownBy(() -> {
      context.putSignRequest(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("signRequest must not be null");
    final SignRequestMessage srm = Mockito.mock(SignRequestMessage.class);
    context.putSignRequest(srm);
    Assertions.assertNotNull(context.getSignRequest());

    assertThatThrownBy(() -> {
      context.putIdentityAssertion(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("identityAssertion must not be null");
    final IdentityAssertion ia = Mockito.mock(IdentityAssertion.class);
    context.putIdentityAssertion(ia);
    Assertions.assertNotNull(context.getIdentityAssertion());

    assertThatThrownBy(() -> {
      context.putSignMessageDisplayed(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("signMessageDisplayed must not be null");
    context.putSignMessageDisplayed(Boolean.FALSE);
    Assertions.assertFalse(context.getSignMessageDisplayed().booleanValue());
  }

}
