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
package se.swedenconnect.signservice.engine;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.client.impl.DefaultClientConfiguration;
import se.swedenconnect.signservice.engine.config.DefaultEngineConfiguration;
import se.swedenconnect.signservice.engine.session.EngineContext;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.MessageConditions;

/**
 * Test cases for DefaultSignRequestMessageVerifier.
 */
public class DefaultSignRequestMessageVerifierTest {

  private static final String SIGNSERVICE_ID = "https://www.example.com/signservice";

  private EngineContext context;

  private DefaultEngineConfiguration config;

  private SignRequestMessage msg;

  @BeforeEach
  public void setup() {
    this.context = Mockito.mock(EngineContext.class);
    Mockito.when(this.context.getId()).thenReturn("ID");

    this.config = new DefaultEngineConfiguration();
    this.config.setName("Name");
    this.config.setSignServiceId(SIGNSERVICE_ID);
    final DefaultClientConfiguration client = new DefaultClientConfiguration();
    client.setClientId("client");
    this.config.setClientConfiguration(client);

    this.msg = Mockito.mock(SignRequestMessage.class);
    Mockito.when(this.msg.getSignServiceId()).thenReturn(SIGNSERVICE_ID);
    Mockito.when(this.msg.getClientId()).thenReturn("client");
    final ProtocolProcessingRequirements ppr = Mockito.mock(ProtocolProcessingRequirements.class);
    Mockito.when(ppr.getRequestSignatureRequirement())
        .thenReturn(ProtocolProcessingRequirements.SignatureRequirement.REQUIRED);
    Mockito.when(this.msg.getProcessingRequirements()).thenReturn(ppr);
    Mockito.when(this.msg.isSigned()).thenReturn(true);
    try {
      Mockito.doNothing().when(this.msg).verifySignature(Mockito.anyList());
    }
    catch (final SignatureException e) {
    }
    Mockito.when(this.msg.getIssuedAt()).thenReturn(Instant.now().minusMillis(100));
    final MessageConditions cond = Mockito.mock(MessageConditions.class);
    Mockito.when(cond.isWithinRange(Mockito.any())).thenReturn(true);
    Mockito.when(msg.getConditions()).thenReturn(cond);
  }

  @Test
  public void testSuccess() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testMismatchingClient() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.getClientId()).thenReturn("client2");
    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("Unknown clientID - ");
  }

  @Test
  public void testMismatchingSignServiceId() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.getSignServiceId()).thenReturn("https://other.signservice.com");
    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("Unexpected SignService ID in request");

    // Should work, but never happens for OASIS DSS ext.
    Mockito.when(this.msg.getSignServiceId()).thenReturn(null);
    Assertions.assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testNotSignedButRequired() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.isSigned()).thenReturn(false);
    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("Request message is not signed");
  }

  @Test
  public void testNotSignedButOptional() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.isSigned()).thenReturn(false);
    final ProtocolProcessingRequirements ppr = Mockito.mock(ProtocolProcessingRequirements.class);
    Mockito.when(ppr.getRequestSignatureRequirement())
        .thenReturn(ProtocolProcessingRequirements.SignatureRequirement.OPTIONAL);
    Mockito.when(this.msg.getProcessingRequirements()).thenReturn(ppr);

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testBadSignature() throws Exception {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();

    Mockito.doThrow(SignatureException.class).when(this.msg).verifySignature(Mockito.anyList());

    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("Request message signature validation failed:");
  }

  @Test
  public void testNoIssuedAt() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.getIssuedAt()).thenReturn(null);

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testIssuedAtTooNew() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    verifier.setAllowedClockSkew(Duration.ofSeconds(30));
    verifier.setMaxMessageAge(null);
    Mockito.when(this.msg.getIssuedAt()).thenReturn(Instant.now().plus(Duration.ofSeconds(31)));

    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("The issued-at field of the sign request indicates that the message is not yet valid");
  }

  @Test
  public void testIssuedAtTooNewSavedByAllowedClockSkew() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    verifier.setAllowedClockSkew(Duration.ofSeconds(30));
    verifier.setMaxMessageAge(null);
    Mockito.when(this.msg.getIssuedAt()).thenReturn(Instant.now().plus(Duration.ofSeconds(29)));

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testIssuedAtTooOld() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    verifier.setAllowedClockSkew(null);
    verifier.setMaxMessageAge(Duration.ofSeconds(60));
    Mockito.when(this.msg.getIssuedAt()).thenReturn(Instant.now().minus(Duration.ofSeconds(91)));

    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("The received sign request message exceeds the maximum allowed age of messages");
  }

  @Test
  public void testIssuedAtTooOldButSavedByClockSkewSetting() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    verifier.setAllowedClockSkew(Duration.ofSeconds(30));
    verifier.setMaxMessageAge(Duration.ofMinutes(3));
    Mockito.when(this.msg.getIssuedAt()).thenReturn(Instant.now().minus(Duration.ofSeconds(208)));

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testMissingConditions() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    Mockito.when(this.msg.getConditions()).thenReturn(null);

    assertDoesNotThrow(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    });
  }

  @Test
  public void testInvalidConditions() {
    final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
    final MessageConditions cond = Mockito.mock(MessageConditions.class);
    Mockito.when(cond.isWithinRange(Mockito.any())).thenReturn(false);
    Mockito.when(this.msg.getConditions()).thenReturn(cond);

    assertThatThrownBy(() -> {
      verifier.verifyMessage(this.msg, this.config, this.context);
    }).isInstanceOf(SignServiceErrorException.class)
        .hasMessage("Verification of notBefore and notAfter condition failed");
  }

}
