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

import java.io.Serializable;

import org.w3c.dom.Element;

import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.schemas.csig.dssext_1_1.SignResponseExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.schemas.dss_1_0.SignResponse;
import se.swedenconnect.schemas.dss_1_0.SignatureObject;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBSerializable;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * A wrapper for a {@link SignResponse} object where we introduce utility methods for access of extension elements.
 */
@Slf4j
class SignResponseWrapper extends SignResponse implements Serializable {

  /** For serializing. */
  private static final long serialVersionUID = -9020476949179208848L;

  /** Object factory for DSS objects. */
  private static se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** The wrapped SignResponse. */
  private final JAXBSerializable<SignResponse> signResponse;

  /** The SignResponseExtension (stored in OptionalOutputs). */
  private transient SignResponseExtension signResponseExtension;

  /**
   * Constructor setting up an empty {@code SignResponse}.
   */
  public SignResponseWrapper() {
    this.signResponse = new JAXBSerializable<>(dssObjectFactory.createSignResponse(), SignResponse.class);
  }

  /**
   * Gets the wrapped SignResponse.
   *
   * @return the wrapped SignResponse
   */
  public SignResponse getWrappedSignResponse() {
    if (this.signResponseExtension != null) {
      this.setSignResponseExtension(this.signResponseExtension);
    }
    return this.signResponse.get();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public SignatureObject getSignatureObject() {
    return this.signResponse.get().getSignatureObject();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public void setSignatureObject(final SignatureObject value) {
    this.signResponse.get().setSignatureObject(value);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetSignatureObject() {
    return this.signResponse.get().isSetSignatureObject();
  }

  /**
   * Utility method that gets the {@code SignTasks} object from the {@code SignatureObject}.
   *
   * @return the SignTasks (or null)
   * @throws DssProtocolException for unmarshalling errors
   */
  public SignTasks getSignTasks() throws DssProtocolException {
    if (this.signResponse.get().getSignatureObject() == null || this.signResponse.get().getSignatureObject().getOther() == null) {
      return null;
    }
    final Element signTasksElement = this.signResponse.get().getSignatureObject()
        .getOther()
        .getAnies()
        .stream()
        .filter(e -> "SignTasks".equals(e.getLocalName()))
        .filter(e -> DssConstants.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signTasksElement != null) {
      try {
        return JAXBUnmarshaller.unmarshall(signTasksElement, SignTasks.class);
      }
      catch (final JAXBException e) {
        log.error("Failed to decode SignTasks element - {}", e.getMessage(), e);
        throw new DssProtocolException("Failed to decode SignTasks", e);
      }
    }
    else {
      return null;
    }
  }

  /**
   * Utility method that add a SignTasks object to {@code Other} object of the {@code SignatureObject}. Any previous
   * sign tasks set in {@code Other} will be overwritten.
   *
   * @param signTasks the object to add
   * @throws DssProtocolException for marshalling errors
   */
  public void setSignTasks(final SignTasks signTasks) throws DssProtocolException {
    if (signTasks == null) {
      // We don't store anything else than SignTasks so ... remove everything
      this.signResponse.get().setSignatureObject(null);
      return;
    }

    if (this.signResponse.get().getSignatureObject() == null) {
      this.signResponse.get().setSignatureObject(dssObjectFactory.createSignatureObject());
    }
    if (this.signResponse.get().getSignatureObject().getOther() == null) {
      this.signResponse.get().getSignatureObject().setOther(dssObjectFactory.createAnyType());
    }

    Element signTasksElement;
    try {
      signTasksElement = JAXBMarshaller.marshall(signTasks).getDocumentElement();
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignTasks - {}", e.getMessage(), e);
      throw new DssProtocolException("Failed to marshall SignTasks", e);
    }
    for (int i = 0; i < this.signResponse.get().getSignatureObject().getOther().getAnies().size(); i++) {
      final Element elm = this.signResponse.get().getSignatureObject().getOther().getAnies().get(i);
      if (elm.getLocalName().equals("SignTasks")) {
        // Overwrite this ...
        this.signResponse.get().getSignatureObject().getOther().getAnies().set(i, signTasksElement);
        return;
      }
    }
    // We didn't have to overwrite. Add it.
    this.signResponse.get().getSignatureObject().getOther().getAnies().add(signTasksElement);
  }

  /** {@inheritDoc} */
  @Override
  public Result getResult() {
    return this.signResponse.get().getResult();
  }

  /** {@inheritDoc} */
  @Override
  public void setResult(final Result value) {
    this.signResponse.get().setResult(value);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetResult() {
    return this.signResponse.get().isSetResult();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public AnyType getOptionalOutputs() {
    return this.signResponse.get().getOptionalOutputs();
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public void setOptionalOutputs(final AnyType value) {
    // Reset our cache for signResponseExtension.
    this.signResponseExtension = null;
    this.signResponse.get().setOptionalOutputs(value);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetOptionalOutputs() {
    return this.signResponse.get().isSetOptionalOutputs();
  }

  /**
   * Gets the {@code SignResponseExtension} element from the {@code OptionalOutput} object.
   *
   * @return the SignResponseExtension (or null)
   * @throws DssProtocolException for unmarshalling errors
   */
  public SignResponseExtension getSignResponseExtension() throws DssProtocolException {
    if (this.signResponseExtension != null) {
      return this.signResponseExtension;
    }
    if (this.signResponse.get().getOptionalOutputs() == null || !this.signResponse.get().getOptionalOutputs().isSetAnies()) {
      return null;
    }
    final Element signResponseExtensionElement = this.signResponse.get().getOptionalOutputs()
        .getAnies()
        .stream()
        .filter(e -> "SignResponseExtension".equals(e.getLocalName()))
        .filter(e -> DssConstants.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signResponseExtensionElement != null) {
      try {
        this.signResponseExtension =
            JAXBUnmarshaller.unmarshall(signResponseExtensionElement, SignResponseExtension.class);
      }
      catch (final JAXBException e) {
        log.error("Failed to decode SignResponseExtension - {}", e.getMessage(), e);
        throw new DssProtocolException("Failed to decode SignResponseExtension", e);
      }
    }
    return this.signResponseExtension;
  }

  /**
   * Assigns the SignResponseExtension by adding it to OptionalOutputs.
   * <p>
   * Note: If the OptionalOutputs already contains data it is overwritten.
   * </p>
   *
   * @param signResponseExtension the extension to add
   * @throws DssProtocolException for JAXB errors
   */
  public void setSignResponseExtension(final SignResponseExtension signResponseExtension) throws DssProtocolException {
    if (signResponseExtension == null) {
      this.signResponse.get().setOptionalOutputs(null);
      this.signResponseExtension = null;
      return;
    }

    try {
      final AnyType optionalOutputs = dssObjectFactory.createAnyType();
      optionalOutputs.getAnies().add(JAXBMarshaller.marshall(signResponseExtension).getDocumentElement());
      this.signResponse.get().setOptionalOutputs(optionalOutputs);
      this.signResponseExtension = signResponseExtension;
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignResponseExtension - {}", e.getMessage(), e);
      throw new DssProtocolException("Failed to marshall SignResponseExtension", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestID() {
    return this.signResponse.get().getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setRequestID(final String value) {
    this.signResponse.get().setRequestID(value);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetRequestID() {
    return this.signResponse.get().isSetRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public String getProfile() {
    return this.signResponse.get().getProfile();
  }

  /** {@inheritDoc} */
  @Override
  public void setProfile(final String value) {
    this.signResponse.get().setProfile(value);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean isSetProfile() {
    return this.signResponse.get().isSetProfile();
  }

}
