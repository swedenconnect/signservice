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

package se.swedenconnect.signservice.signature.tbsdata.impl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

import javax.annotation.Nonnull;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.SimpleTimeZone;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFTBSDataProcessor implements TBSDataProcessor {

  @Override public TBSProcessingData getTBSData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signingCredential, "Signing credentials must not be null");
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");

    byte[] tbsBytes = Optional.ofNullable(signatureTask.getTbsData())
      .orElseThrow(() -> new SignatureException("Null data to be sign in sign request"));


    return null;
  }


  public static Date getCmsSigningTime(byte[] cmsSigAttr){
    try{
      ASN1Object a1o = new ASN1InputStream(cmsSigAttr).readObject();
      int cnt = a1o.;
      for (int i=0;i<cnt;i++){
        ASN1Object seqObj = a1o.getComponentAt(i);
        if (seqObj instanceof SEQUENCE){
          SEQUENCE  seq = (SEQUENCE) seqObj;
          ObjectID attrOid = (ObjectID) seq.getComponentAt(0);
          // if signing time
          if (attrOid.equals(new ObjectID("1.2.840.113549.1.9.5"))){
            UTCTime utcSigTime = (UTCTime) seq.getComponentAt(1).getComponentAt(0);
            String value = (String) utcSigTime.getValue();
            DateFormat df = new SimpleDateFormat("yyMMddHHmmss'Z'");
            df.setTimeZone(new SimpleTimeZone(0,"Z"));
            Date sigDate = (Date) df.parse(value);
            return sigDate;
          }
        }

      }
    }catch(Exception ex){
    }
    return null;
  }


}
