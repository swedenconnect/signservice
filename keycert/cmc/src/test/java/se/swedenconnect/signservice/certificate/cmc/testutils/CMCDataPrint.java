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
package se.swedenconnect.signservice.certificate.cmc.testutils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.GetCert;
import org.bouncycastle.asn1.cmc.LraPopWitness;
import org.bouncycastle.asn1.cmc.OtherStatusInfo;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.util.encoders.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;

import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Test result data printing
 */
public class CMCDataPrint {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public static String printCMCRequest(CMCRequest cmcRequest, boolean includeFullMessage, boolean includeCertRequest) {

    if (cmcRequest == null) {
      return "Null CMC Request";
    }

    try {
      StringBuilder b = new StringBuilder();
      CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      b.append("CMC request type: ").append(cmcRequestType).append("\n");
      PKIData pkiData = cmcRequest.getPkiData();
      b.append("  time: ").append(CMCUtils.getSigningTime(cmcRequest.getCmcRequestBytes())).append("\n");
      TaggedAttribute[] controlSequence = pkiData.getControlSequence();
      if (controlSequence.length > 0) {
        b.append("CMC Control sequence (size=").append(controlSequence.length).append(")\n");
        for (TaggedAttribute csAttr : controlSequence) {
          CMCControlObjectID controlObjectID = CMCControlObjectID.getControlObjectID(csAttr.getAttrType());
          b.append("  type: ").append(controlObjectID).append("\n");
          printControlValue(cmcRequestType, controlObjectID, csAttr, b);
        }
      }

      if (CMCRequestType.issueCert.equals(cmcRequestType)) {
        printIssueCert(pkiData, includeCertRequest, b);
      }

      if (includeFullMessage) {
        b.append("  Full CMC request:\n").append(base64Print(cmcRequest.getCmcRequestBytes(), 120)).append("\n");
      }

      return b.toString();
    }
    catch (Exception ex) {
      return "Error parsing CMC request: " + ex.toString() + "\n";
    }
  }

  public static String printCMCResponse(CMCResponse cmcResponse, boolean includeFullMessage) {
    if (cmcResponse == null) {
      return "Null CMC Request";
    }

    try {
      StringBuilder b = new StringBuilder();
      Base64.toBase64String(cmcResponse.getCmcResponseBytes());
      PKIResponse pkiResponse = cmcResponse.getPkiResponse();
      TaggedAttribute[] responseControlSequence = CMCUtils.getResponseControlSequence(pkiResponse);
      b.append("CMC Request type: ").append(cmcResponse.getCmcRequestType()).append("\n");
      b.append("  time: ").append(CMCUtils.getSigningTime(cmcResponse.getCmcResponseBytes())).append("\n");
      if (responseControlSequence.length > 0) {
        b.append("CMC Control sequence (size=").append(responseControlSequence.length).append(")\n");
        for (TaggedAttribute csAttr : responseControlSequence) {
          CMCControlObjectID controlObjectID = CMCControlObjectID.getControlObjectID(csAttr.getAttrType());
          b.append("  type: ").append(controlObjectID).append("\n");
          printControlValue(null, controlObjectID, csAttr, b);
        }
      }

      List<X509Certificate> returnCertificates = cmcResponse.getReturnCertificates();
      if (returnCertificates != null) {
        for (X509Certificate certificate : returnCertificates) {
          b.append("  ReturnCert: ").append(certificate.getSubjectX500Principal()).append("\n");
          b.append("    Certificate bytes:\n").append(base64Print(certificate.getEncoded(), 120)).append("\n");
        }
      }

      if (includeFullMessage) {
        b.append("  Full CMC response:\n").append(base64Print(cmcResponse.getCmcResponseBytes(), 120)).append("\n");
      }

      return b.toString();
    }
    catch (Exception ex) {
      return "Error parsing CMC request: " + ex.toString() + "\n";
    }
  }

  private static void printControlValue(CMCRequestType cmcRequestType, CMCControlObjectID controlObjectID,
      TaggedAttribute csAttr,
      StringBuilder b) {
    ASN1Set attrValues = csAttr.getAttrValues();
    for (int i = 0; i < attrValues.size(); i++) {
      ASN1Encodable asn1Encodable = attrValues.getObjectAt(i);
      String valueStr = "";
      try {
        switch (controlObjectID) {

        case senderNonce:
        case recipientNonce:
          valueStr = Base64.toBase64String(ASN1OctetString.getInstance(asn1Encodable).getOctets());
          b.append("    value: ").append(valueStr).append("\n");
          break;
        case regInfo:
          byte[] octets = ASN1OctetString.getInstance(asn1Encodable).getOctets();
          if (cmcRequestType == null) {
            break;
          }
          switch (cmcRequestType) {
          case issueCert:
            valueStr = new String(octets, StandardCharsets.UTF_8);
            b.append("    value: ").append(valueStr).append("\n");
            break;
          case revoke:
          case getCert:
            valueStr = Base64.toBase64String(octets);
            b.append("    value: ").append(valueStr).append("\n");
            break;
          case admin:
            AdminCMCData adminRequestData = OBJECT_MAPPER.readValue(octets, AdminCMCData.class);
            b.append("    admin-type: ").append(adminRequestData.getAdminRequestType()).append("\n");
            String requestData = adminRequestData.getData();
            if (requestData != null) {
              valueStr = OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
                  OBJECT_MAPPER.readValue(requestData, Object.class));
              b.append("    request-data:\n").append(valueStr.replaceAll("(?m)^", "      ")).append("\n");
            }
            break;
          }
          break;
        case lraPOPWitness:
          LraPopWitness lraPopWitness = LraPopWitness.getInstance(asn1Encodable);
          BodyPartID[] bodyIds = lraPopWitness.getBodyIds();
          for (BodyPartID bodyPartID : bodyIds) {
            b.append("    POP witness ID: ").append(bodyPartID.getID()).append("\n");
          }
          break;
        case getCert:
          GetCert getCert = GetCert.getInstance(asn1Encodable);
          String issuerName = getCert.getIssuerName().toString();
          String certSerial = getCert.getSerialNumber().toString(16);
          b.append("    cert-serial: ").append(certSerial).append("\n");
          b.append("    issuer: ").append(issuerName).append("\n");
          break;
        case revokeRequest:
          RevokeRequest revokeRequest = RevokeRequest.getInstance(asn1Encodable);
          b.append("    cert-serial: ").append(revokeRequest.getSerialNumber().toString(16)).append("\n");
          b.append("    ").append(revokeRequest.getReason()).append("\n");
          b.append("    date: ").append(revokeRequest.getInvalidityDate().getDate()).append("\n");
          b.append("    issuer: ").append(revokeRequest.getName()).append("\n");
          break;
        case statusInfoV2:
          CMCStatusInfoV2 statusInfoV2 = CMCStatusInfoV2.getInstance(asn1Encodable);
          CMCFailType cmcFailType = getCmcFailType(statusInfoV2);
          CMCStatusType cmcStatus = CMCStatusType.getCMCStatusType(statusInfoV2.getCMCStatus());
          @SuppressWarnings("deprecation")
          DERUTF8String statusString = statusInfoV2.getStatusString();
          b.append("    CMC status: ").append(cmcStatus).append("\n");
          BodyPartID[] bodyList = statusInfoV2.getBodyList();
          for (BodyPartID bodyPartID : bodyList) {
            b.append("      Processed object: ").append(bodyPartID.getID()).append("\n");
          }
          if (cmcFailType != null) {
            b.append("    CMC fail info: ").append(cmcFailType).append("\n");
          }
          if (statusString != null) {
            b.append("    status string: ").append(statusString.getString()).append("\n");
          }
          break;
        case responseInfo:
          byte[] responseInfoData = ASN1OctetString.getInstance(asn1Encodable).getOctets();
          try {
            AdminCMCData adminCMCData = CMCUtils.OBJECT_MAPPER.readValue(responseInfoData, AdminCMCData.class);
            b.append("    admin-type: ").append(adminCMCData.getAdminRequestType()).append("\n");
            String responseData = adminCMCData.getData();
            if (responseData != null) {
              valueStr = OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
                  OBJECT_MAPPER.readValue(responseData, Object.class));
              b.append("    response-data:\n").append(valueStr.replaceAll("(?m)^", "      ")).append("\n");
            }
          }
          catch (Exception ex) {
            // This was not admin json data. Check if this is a string value
            String responseInfoString = TestUtils.base64Print(responseInfoData);
            b.append("    response-data: ").append(responseInfoString).append("\n");
          }
          break;
        default:
          b.append("    Encoded control data: ")
              .append(Base64.toBase64String(asn1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER)))
              .append("\n");
          break;
        }
      }
      catch (Exception ex) {
        b.append("    value-error: ").append(ex.toString()).append("\n");
        b.append("    value: ").append(valueStr).append("\n");
      }
    }
  }

  public static CMCFailType getCmcFailType(CMCStatusInfoV2 statusInfoV2) {
    OtherStatusInfo otherStatusInfo = statusInfoV2.getOtherStatusInfo();
    if (otherStatusInfo != null && otherStatusInfo.isFailInfo()) {
      CMCFailInfo cmcFailInfo = CMCFailInfo.getInstance(otherStatusInfo.toASN1Primitive());
      return CMCFailType.getCMCFailType(cmcFailInfo);
    }
    return null;
  }

  private static void printIssueCert(PKIData pkiData, boolean includeCertRequest, StringBuilder b) throws IOException {
    TaggedRequest[] reqSequence = pkiData.getReqSequence();
    for (TaggedRequest taggedRequest : reqSequence) {
      ASN1Encodable taggedRequestValue = taggedRequest.getValue();
      if (taggedRequestValue instanceof TaggedCertificationRequest) {
        TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
        ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
        BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
        CertificationRequest certificationRequest = CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
        b.append("  Certificate request: PKCS#10 Certificate Request\n");
        b.append("    Body part ID: ").append(certReqBodyPartId.getID()).append("\n");
        if (includeCertRequest) {
          b.append("    Certificate Request:\n")
              .append(base64Print(certificationRequest.getEncoded(ASN1Encoding.DER), 120)).append("\n");
        }
        return;
      }
      if (taggedRequestValue instanceof CertReqMsg) {
        CertificateRequestMessage certificateRequestMessage =
            new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
        ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
        BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
        b.append("  Certificate request: CRMF Certificate Request Message\n");
        b.append("    Body part ID: ").append(certReqBodyPartId.getID()).append("\n");
        if (includeCertRequest) {
          b.append("    Certificate Request:\n").append(base64Print(certificateRequestMessage.getEncoded(), 120))
              .append("\n");
        }
        return;
      }
      b.append(" Certificate request: Unknown request type\n");
    }
  }

  private static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }

}
