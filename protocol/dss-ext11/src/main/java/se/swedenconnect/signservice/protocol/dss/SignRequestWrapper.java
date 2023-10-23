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
package se.swedenconnect.signservice.protocol.dss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import javax.xml.bind.JAXBException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.InputDocuments;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;

/**
 * A wrapper for easier access to the DSS extensions.
 */
@Slf4j
class SignRequestWrapper extends SignRequest implements Serializable {

  /** For serialization. */
  private static final long serialVersionUID = 414996066434815557L;

  /** Object factory for DSS objects. */
  private static se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** The wrapped SignRequest. */
  private SignRequest signRequest;

  /** The SignRequest extension (stored in OptionalInputs). */
  private SignRequestExtension signRequestExtension;

  /** The SignTasks element (stored in InputDocuments). */
  private SignTasks signTasks;

  /**
   * Constructor setting up an empty {@code SignRequest}.
   */
  public SignRequestWrapper() {
    this.signRequest = dssObjectFactory.createSignRequest();
  }

  /**
   * Constructor.
   *
   * @param signRequest the request to wrap.
   */
  public SignRequestWrapper(final SignRequest signRequest) {
    this.signRequest = signRequest;
  }

  /**
   * Gets the wrapped SignRequest object.
   *
   * @return the wrapped SignRequest object
   */
  public SignRequest getWrappedSignRequest() {
    return this.signRequest;
  }

  /**
   * Utility method that obtains the SignRequestExtension (from the OptionalInputs).
   *
   * @return the SignRequestExtension
   */
  public SignRequestExtension getSignRequestExtension() {
    if (this.signRequestExtension != null) {
      return this.signRequestExtension;
    }
    if (!this.signRequest.isSetOptionalInputs()) {
      return null;
    }
    final Element signRequestExtensionElement = this.signRequest.getOptionalInputs()
        .getAnies()
        .stream()
        .filter(e -> "SignRequestExtension".equals(e.getLocalName()))
        .filter(e -> DssConstants.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signRequestExtensionElement != null) {
      try {
        this.signRequestExtension = JAXBUnmarshaller.unmarshall(
            signRequestExtensionElement, SignRequestExtension.class);
      }
      catch (final JAXBException e) {
        log.info("Failed to unmarshall SignRequestExtension - {}", e.getMessage(), e);
        throw new DssProtocolException("Failed to unmarshall SignRequestExtension", e);
      }
    }
    return this.signRequestExtension;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public AnyType getOptionalInputs() {
    return this.signRequest.getOptionalInputs();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetOptionalInputs() {
    return this.signRequest.isSetOptionalInputs();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public InputDocuments getInputDocuments() {
    return this.signRequest.getInputDocuments();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public void setInputDocuments(final InputDocuments value) {
    // Reset the signTasks variable. It may be set as an any type in the supplied value.
    this.signTasks = null;
    this.signRequest.setInputDocuments(value);
  }

  /**
   * Utility method that obtains the SignTasks element from the InputDocuments.
   *
   * @return the SignTasks element or null
   */
  public SignTasks getSignTasks() {
    if (this.signTasks != null) {
      return this.signTasks;
    }
    if (this.signRequest.getInputDocuments() == null
        || !this.signRequest.getInputDocuments().isSetDocumentsAndTransformedDatasAndDocumentHashes()) {
      return null;
    }
    for (final Object o : this.signRequest.getInputDocuments().getDocumentsAndTransformedDatasAndDocumentHashes()) {
      if (o instanceof AnyType) {
        final Element signTasksElement = ((AnyType) o).getAnies()
            .stream()
            .filter(e -> "SignTasks".equals(e.getLocalName()))
            .filter(e -> DssConstants.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
            .findFirst()
            .orElse(null);
        if (signTasksElement != null) {
          try {
            this.signTasks = JAXBUnmarshaller.unmarshall(signTasksElement, SignTasks.class);
            return this.signTasks;
          }
          catch (final JAXBException e) {
            log.error("Failed to unmarshall SignTasks - {}", e.getMessage(), e);
            throw new DssProtocolException("Failed to decode SignTasks", e);
          }
        }
      }
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetInputDocuments() {
    return this.signRequest.isSetInputDocuments();
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestID() {
    return this.signRequest.getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setRequestID(final String value) {
    this.signRequest.setRequestID(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetRequestID() {
    return this.signRequest.isSetRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public String getProfile() {
    return this.signRequest.getProfile();
  }

  /** {@inheritDoc} */
  @Override
  public void setProfile(final String value) {
    this.signRequest.setProfile(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetProfile() {
    return this.signRequest.isSetProfile();
  }

  /**
   * For serialization of the object.
   *
   * @param out the output stream
   * @throws IOException for errors
   */
  private void writeObject(final ObjectOutputStream out) throws IOException {
    try {
      final Document document = JAXBMarshaller.marshall(this.signRequest);
      final byte[] bytes = DOMUtils.nodeToBytes(document);
      out.writeObject(bytes);
    }
    catch (final JAXBException | InternalXMLException e) {
      throw new IOException("Could not marshall SignRequest", e);
    }
  }

  /**
   * For deserialization of the object
   *
   * @param in the input stream
   * @throws IOException for errors
   * @throws ClassNotFoundException not thrown by this method
   */
  private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    try {
      final byte[] bytes = (byte[]) in.readObject();
      final Document document = DOMUtils.bytesToDocument(bytes);
      this.signRequest = JAXBUnmarshaller.unmarshall(document, SignRequest.class);
    }
    catch (final JAXBException | InternalXMLException e) {
      throw new IOException("Could not restore SignRequest", e);
    }
  }

}
