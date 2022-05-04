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
package se.swedenconnect.signservice.protocol.dss;

import java.util.Objects;
import java.util.Optional;

import javax.xml.bind.JAXBException;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.signservice.protocol.msg.SignMessage;

/**
 * Representation of a DSS SignMessage.
 */
@Slf4j
class DssSignMessage implements SignMessage {

  /** For serializing. */
  private static final long serialVersionUID = -2976874546991075421L;

  /** The DSS SignMessage. */
  private transient se.swedenconnect.schemas.csig.dssext_1_1.SignMessage dssSignMessage;

  /** The encoding. */
  private final byte[] encoding;

  /**
   * Constructor.
   *
   * @param signMessage the DSS sign message
   */
  public DssSignMessage(final se.swedenconnect.schemas.csig.dssext_1_1.SignMessage signMessage) {
    this.dssSignMessage = Objects.requireNonNull(signMessage, "signMessage must not be null");
    this.encoding = Optional.of(this.dssSignMessage)
        .map(m -> {
          try {
            return JAXBMarshaller.marshall(m);
          }
          catch (final JAXBException e) {
            log.info("Invalid SignMessage - failed to marshall it", e);
            return null;
          }
        })
        .map(d -> DOMUtils.nodeToBytes(d))
        .orElseThrow(() -> new IllegalArgumentException("Invalid SignMessage"));
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getEncoding() {
    return this.encoding.clone();
  }

  /**
   * Gets the DSS SignMessage.
   *
   * @return the DSS SignMessage
   */
  public se.swedenconnect.schemas.csig.dssext_1_1.SignMessage getDssSignMessage() {
    if (this.dssSignMessage == null) {
      try {
      this.dssSignMessage =
          JAXBUnmarshaller.unmarshall(DOMUtils.bytesToDocument(this.encoding),
              se.swedenconnect.schemas.csig.dssext_1_1.SignMessage.class);
      }
      catch (final JAXBException e) {
        // Should never happen ...
        log.warn("Failed to unmarshall SignMessage");
        throw new RuntimeException(e);
      }
    }
    return this.dssSignMessage;
  }

  /** {@inheritDoc} */
  @Override
  public boolean getMustShow() {
    return this.getDssSignMessage().isMustShow();
  }

}
