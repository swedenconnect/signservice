/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.EntityType;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.*;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.GenericExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.SubjDirectoryAttributesModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.AlternativeNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.cert.extensions.InhibitAnyPolicy;
import se.swedenconnect.cert.extensions.PrivateKeyUsagePeriod;
import se.swedenconnect.cert.extensions.QCStatements;
import se.swedenconnect.cert.extensions.data.MonetaryValue;
import se.swedenconnect.cert.extensions.data.PDSLocation;
import se.swedenconnect.cert.extensions.data.SemanticsInformation;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Generating basic certificate request data for test
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertRequestData {

  public static CertNameModel getCompleteSubjectName() {
    CertNameModel subjectName = new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.C)
        .value("SE").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.O)
        .value("Organization AB").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.OU)
        .value("Dev department").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.SERIALNUMBER)
        .value("196405065683").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.GIVENNAME)
        .value("Nisse").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.SURNAME)
        .value("Hult").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.CN)
        .value("Nisse Hult").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.T)
        .value("CEO").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.EmailAddress)
        .value("nisse.hult@example.com").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.DATE_OF_BIRTH)
        .value("1964-05-06").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.ORGANIZATION_IDENTIFIER)
        .value("556778-1122").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.DC)
        .value("example.com").build()
    ));
    return subjectName;
  }

  public static CertNameModel getTypicalSubejctName(String givenName, String surname, String id) {
    CertNameModel subjectName = new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.C)
        .value("SE").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.SERIALNUMBER)
        .value(id).build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.GIVENNAME)
        .value(givenName).build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.SURNAME)
        .value(surname).build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.CN)
        .value(givenName + " " + surname).build()
    ));
    return subjectName;
  }

  public static CertNameModel getTypicalServiceName(String commonName, String country) {
    CertNameModel subjectName = new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.C)
        .value(country).build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.O)
        .value("Organization AB").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.OU)
        .value("Service department").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.ORGANIZATION_IDENTIFIER)
        .value("556677-1122").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.CN)
        .value(commonName).build()
    ));
    return subjectName;
  }

  public static DefaultCertificateModelBuilder getCompleteCertModelBuilder(PublicKey publicKey, X509CertificateHolder issuerCert,
    CertificateIssuerModel issuerModel) {
    DefaultCertificateModelBuilder builder = DefaultCertificateModelBuilder.getInstance(publicKey, issuerCert, issuerModel);
    builder
      .subject(getCompleteSubjectName())
      .basicConstraints(new BasicConstraintsModel(3, true))
      .includeAki(true)
      .includeSki(true)
      .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign + KeyUsage.digitalSignature, true))
      .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_OCSPSigning))
      .crlDistributionPoints(Arrays.asList("http://example.com/crl1", "http://example.com/crl2"))
      .ocspServiceUrl("http://example.com/ocsp")
      .issuerCertUrl("http://example.com/issuerCert")
      .certificatePolicy(new CertificatePolicyModel(true, Arrays.asList(
        CertificatePolicyModel.PolicyInfoParams.builder()
          .policy(new ASN1ObjectIdentifier("1.2.3.4.5"))
          .cpsUri("https://example.com/cps")
          .displayText("Detta är en display text ")
          .build(),
        CertificatePolicyModel.PolicyInfoParams.builder()
          .policy(new ASN1ObjectIdentifier("1.2.3.4.6"))
          .cpsUri("https://example.com/cps2")
          .displayText("Detta är en annan display text ")
          .build()
      )))
      .authenticationContext(SAMLAuthContextBuilder.instance()
        .assertionRef("091283098123098123")
        .authenticationInstant(new Date())
        .authnContextClassRef("https://example.com/loa/loa3")
        .identityProvider("https://example.com/idp")
        .serviceID("http://example.com/service-provider")
        .attributeMappings(Arrays.asList(
          AttributeMappingBuilder.instance()
            .name("name1").friendlyName("fName1").nameFormat("nameFormat")
            .ref("2.5.4.1").type(AttributeRefType.rdn)
            .build(),
          AttributeMappingBuilder.instance()
            .name("name2").friendlyName("fName2").nameFormat("nameFormat")
            .ref("2.5.4.2").type(AttributeRefType.rdn)
            .build(),
          AttributeMappingBuilder.instance()
            .name("name3").friendlyName("fName3").nameFormat("nameFormat")
            .ref("6").type(AttributeRefType.san)
            .build()
        ))
        .build())
      .caRepositoryUrl("http://example.com/certs")
      .timeStampAuthorityUrl("http://example.com/timestamps")
      .qcStatements(QcStatementsBuilder.instance()
        .versionAndSemantics(new QCPKIXSyntax(new SemanticsInformation(QCStatements.ETSI_SEMANTICS_EIDAS_NATURAL, Arrays.asList(
          new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com/name-reg-authority-01"),
          new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com/name-reg-authority-02")))))
        .qualifiedCertificate(true)
        .qscd(true)
        .qcTypes(Arrays.asList(QCStatements.QC_TYPE_ELECTRONIC_SIGNATURE))
        .legislationCountries(Arrays.asList("SE", "NO"))
        .relianceLimit(new MonetaryValue("SEK", new BigInteger("1"), new BigInteger("3")))
        .retentionPeriod(10)
        .pdsLocations(Arrays.asList(
          new PDSLocation("sv", "https://example.com/pds-location-sv"),
          new PDSLocation("en", "https://example.com/pds-location-en")))
        .build())
      .subjectAltNames(Collections.singletonMap(GeneralName.uniformResourceIdentifier, "https://example.com/alt-name-uri"))
      .subjectDirectoryAttributes(new SubjDirectoryAttributesModel(Arrays.asList(
        new AttributeModel(CertAttributes.POSTAL_ADDRESS, "Scheelevägen 12", "223 70 Lund"),
        new AttributeModel(CertAttributes.DATE_OF_BIRTH, "1962-11-02"),
        new AttributeModel(CertAttributes.PLACE_OF_BIRTH, "Malmö"),
        new AttributeModel(CertAttributes.GENDER, "M"),
        new AttributeModel(CertAttributes.COUNTRY_OF_CITIZENSHIP, "SE", "DE")
      )))
      .ocspNocheck(true);
    return builder;

  }

  public static void addUncommonExtensions(CertificateModel certificateModel) {
    // Add uncommon extensions
    // IssuerAlternativeName
    List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    extensionModels.add(new AlternativeNameModel(EntityType.issuer,
      new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.com/alt-name-uri")));

    // InhibitAnyPolicy (Must be critical)
    extensionModels.add(new GenericExtensionModel(
      Extension.inhibitAnyPolicy, new InhibitAnyPolicy(1), true
    ));

    // NameConstraints (MUST be critical)
    extensionModels.add(new GenericExtensionModel(
      Extension.nameConstraints, new NameConstraints(
      new GeneralSubtree[] {
        new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "example.com"))
      },
      new GeneralSubtree[] {
        new GeneralSubtree(new GeneralName(1, "example.com"))
      }), true
    ));

    // PolicyConstraints (Must be critical)
    extensionModels.add(new GenericExtensionModel(
      Extension.policyConstraints, new PolicyConstraints(new BigInteger("1"), new BigInteger("1")), true
    ));
    // PolicyMappings
    extensionModels.add(new GenericExtensionModel(
      Extension.policyMappings, new PolicyMappings(
      new CertPolicyId[] { CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.2.3.4.5.6")),
        CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.2.3.4.5.7")) },
      new CertPolicyId[] { CertPolicyId.getInstance(new ASN1ObjectIdentifier("2.2.3.4.5.6")),
        CertPolicyId.getInstance(new ASN1ObjectIdentifier("2.2.3.4.5.7")) }
    ), true));

    // PrivateKeyUsagePeriod
    extensionModels.add(new GenericExtensionModel(
      Extension.privateKeyUsagePeriod, new PrivateKeyUsagePeriod(new Date(), new Date(new Date().getTime() + 1000 * 60 * 60 * 24 * 365 * 5))
    ));
  }

}
