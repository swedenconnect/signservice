/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.protocol.types;

import java.io.Serializable;
import java.time.Instant;

/**
 * Represents "conditions" that appears in a SignService message.
 */
public interface MessageConditions extends Serializable {

  /**
   * Tells that the message must not be regarded as valid before this instant.
   *
   * @return not before instant
   */
  Instant getNotBefore();

  /**
   * Tells that the message must not be regarded as valid after this instant.
   *
   * @return not after instant
   */
  Instant getNotAfter();

}
