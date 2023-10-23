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
package se.swedenconnect.signservice.signature.tbsdata;

import java.security.SignatureException;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.bind.JAXBException;

import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.etsi.xades_1_3_2.DigestAlgAndValueType;
import se.swedenconnect.schemas.etsi.xades_1_3_2.QualifyingProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignaturePolicyIdentifier;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificate;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificateV2;

/**
 * The XAdES object for XML signatures is a {@code xades:QualifyingProperties} object.
 */
@Slf4j
public class XadesQualifyingProperties {

  /** XAdES namespace. */
  public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

  /** The local name for the QualifyingProperties element. */
  public static final String LOCAL_NAME = "QualifyingProperties";

  /** Object factory for XAdES objects. */
  private static final se.swedenconnect.schemas.etsi.xades_1_3_2.ObjectFactory xadesObjectFactory =
      new se.swedenconnect.schemas.etsi.xades_1_3_2.ObjectFactory();

  /** Object factory for ds objects. */
  private static final org.apache.xml.security.binding.xmldsig.ObjectFactory dsObjectFactory =
      new org.apache.xml.security.binding.xmldsig.ObjectFactory();

  /** The ds:Object holding the QualifyingProperties. */
  private ObjectType dsObject;

  /** The XAdES object. */
  private QualifyingProperties qualifyingProperties;

  /** Flag telling whether the QualifyingProperties has been updated. */
  private boolean updated = false;

  /**
   * Constructor.
   *
   * @param dsObject
   *          the ds:Object holding the QualifyingProperties element
   * @throws SignatureException
   *           for protocol errors
   */
  public XadesQualifyingProperties(@Nonnull final ObjectType dsObject) throws SignatureException {
    try {
      this.dsObject = Objects.requireNonNull(dsObject, "dbObject must not be null");
      for (final Object child : this.dsObject.getContent()) {
        if (child instanceof QualifyingProperties) {
          this.qualifyingProperties = (QualifyingProperties) child;
          break;
        }
        else if (child instanceof Element) {
          final Element elm = (Element) child;
          if (XadesQualifyingProperties.LOCAL_NAME.equals(elm.getLocalName())) {
            this.qualifyingProperties = JAXBUnmarshaller.unmarshall(elm, QualifyingProperties.class);
            break;
          }
        }
      }
      if (this.qualifyingProperties == null) {
        final String msg = "No QualifyingProperties element found in XAdES object";
        log.info("{}", msg);
        throw new SignatureException(msg);
      }
    }
    catch (final JAXBException e) {
      final String msg = "Invalid QualifyingProperties element found in XAdES object";
      log.error("{}", msg, e);
      throw new SignatureException(msg, e);
    }
  }

  /**
   * Creates a {@code XadesQualifyingProperties} from a DOM element.
   *
   * @param dsObject
   *          DOM element of the ds:Object holding the QualifyingProperties element
   * @return a XadesQualifyingProperties object
   * @throws SignatureException
   *           for protocol errors
   */
  @Nonnull
  public static XadesQualifyingProperties createXadesQualifyingProperties(@Nonnull final Element dsObject) throws SignatureException {
    try {
      return new XadesQualifyingProperties(JAXBUnmarshaller.unmarshall(dsObject, ObjectType.class));
    }
    catch (final JAXBException e) {
      final String msg = "Invalid QualifyingProperties element found in XAdES object";
      log.info("{}", msg, e);
      throw new SignatureException(msg, e);
    }
  }

  /**
   * Creates a {@code XadesQualifyingProperties} with a {@code ds:Object} holding a {@code xades:QualifyingProperties}
   * with no content.
   *
   * @return a XadesQualifyingProperties object
   * @throws SignatureException
   *           for protocol errors
   */
  @Nonnull
  public static XadesQualifyingProperties createXadesQualifyingProperties() throws SignatureException {
    try {
      final ObjectType dsObject = dsObjectFactory.createObjectType();
      final QualifyingProperties qp = xadesObjectFactory.createQualifyingProperties();
      dsObject.getContent().add(JAXBMarshaller.marshall(qp).getDocumentElement());
      return new XadesQualifyingProperties(dsObject);
    }
    catch (final JAXBException e) {
      final String msg = "Failed to marshall QualifyingProperties element";
      log.info("{}", msg, e);
      throw new SignatureException(msg, e);
    }
  }

  /**
   * Gets the DOM element of the AdES object (which is a {@code ds:Object} containing a
   * {@code xades:QualifyingProperties}).
   *
   * @return the DOM element for the AdES object
   * @throws JAXBException
   *           for marshalling errors
   */
  @Nonnull
  public Element getAdesElement() throws JAXBException {
    if (this.updated) {
      // OK, the qualifying properties were updated, lets look the element up and replace it...
      //
      for (int i = 0; i < this.dsObject.getContent().size(); i++) {
        final Object child = this.dsObject.getContent().get(i);
        if (QualifyingProperties.class.isInstance(child)
            || Element.class.isInstance(child) && XadesQualifyingProperties.LOCAL_NAME.equals(((Element) child).getLocalName())) {

          this.dsObject.getContent().set(i, JAXBMarshaller.marshall(this.qualifyingProperties).getDocumentElement());
          this.updated = false;
          break;
        }
      }
    }
    return JAXBMarshaller.marshallNonRootElement(dsObjectFactory.createObject(this.dsObject)).getDocumentElement();
  }

  /**
   * Gets the AdES digest of the signing certificate.
   * @return AdES digest of the signing certificate
   */
  @Nullable
  public AdesSigningCertificateDigest getSigningCertificateDigest() {
    if (this.qualifyingProperties.getSignedProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() != null) {

      DigestAlgAndValueType digest = null;

      if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificateV2() != null) {
        final SigningCertificateV2 signingCert =
            this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificateV2();
        if (!signingCert.getCerts().isEmpty() && signingCert.getCerts().get(0).getCertDigest() != null) {
          digest = signingCert.getCerts().get(0).getCertDigest();
        }
      }
      else if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificate() != null) {
        final SigningCertificate signingCert =
            this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningCertificate();
        if (!signingCert.getCerts().isEmpty() && signingCert.getCerts().get(0).getCertDigest() != null) {
          log.info("XAdES object contains <xades:SigningCertificate>. Should be <xades:SigningCertificateV2>");
          digest = signingCert.getCerts().get(0).getCertDigest();
        }
      }
      if (digest != null) {
        if (digest.getDigestMethod() != null && digest.getDigestMethod().getAlgorithm() != null && digest.getDigestValue() != null) {
          return AdesSigningCertificateDigest.builder()
            .digestMethod(digest.getDigestMethod().getAlgorithm())
            .digestValue(digest.getDigestValue())
            .build();
        }
      }
    }
    log.info("No signing certificate digest available in xades:QualifyingProperties");
    return null;
  }

  /**
   * Gets the {@code xades:SigningTime}.
   *
   * @return the signing time (in millis since epoch), or null if it is not available
   */
  @Nullable
  public Long getSigningTime() {
    if (this.qualifyingProperties.getSignedProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningTime() != null) {

      return this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSigningTime()
        .toGregorianCalendar().getTimeInMillis();
    }
    return null;
  }

  /**
   * Gets the SignaturePolicyIdentifier or null
   *
   * @return the SignaturePolicyIdentifier or null
   */
  @Nullable
  public SignaturePolicyIdentifier getSignaturePolicyIdentifier() {
    if (this.qualifyingProperties.getSignedProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() != null
        && this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier() != null) {
      return this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier();
    }
    return null;
  }

  /**
   * Assigns the signature policy ID to the XAdES object.
   *
   * @param signaturePolicy
   *          the ID to assign
   * @return whether the object was updated
   */
  public boolean setSignaturePolicy(@Nonnull final String signaturePolicy) {
    if (this.qualifyingProperties.getSignedProperties() == null) {
      this.qualifyingProperties.setSignedProperties(xadesObjectFactory.createSignedProperties());
      this.updated = true;
    }
    if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties() == null) {
      this.qualifyingProperties.getSignedProperties().setSignedSignatureProperties(xadesObjectFactory.createSignedSignatureProperties());
      this.updated = true;
    }
    if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier() == null) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().setSignaturePolicyIdentifier(
        xadesObjectFactory.createSignaturePolicyIdentifier());
      this.updated = true;
    }
    if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier()
      .getSignaturePolicyId() == null) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().setSignaturePolicyId(
        xadesObjectFactory.createSignaturePolicyIdType());
      this.updated = true;
    }
    if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
      .getSigPolicyId() == null) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
        .setSigPolicyId(
          xadesObjectFactory.createObjectIdentifier());
      this.updated = true;
    }
    if (this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
      .getSigPolicyId().getIdentifier() == null) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
        .getSigPolicyId().setIdentifier(
          xadesObjectFactory.createIdentifierType());
      this.updated = true;
    }
    final String value =
        this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
          .getSigPolicyId().getIdentifier().getValue();
    if (value == null) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
        .getSigPolicyId().getIdentifier().setValue(signaturePolicy);
      this.updated = true;
    }
    else if (!value.equals(signaturePolicy)) {
      this.qualifyingProperties.getSignedProperties().getSignedSignatureProperties().getSignaturePolicyIdentifier().getSignaturePolicyId()
        .getSigPolicyId().getIdentifier().setValue(signaturePolicy);
      this.updated = true;
    }

    return this.updated;
  }

}
