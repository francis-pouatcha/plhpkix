package org.adorys.plh.pkix.core.cmp.certrequest;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds an initial certification request. The subject's environment generates a 
 * key pair, generates a self signed certificate and envelopes it into a 
 * certification request that is sent to the intended certification authority.
 * 
 * @author francis
 *
 */
public class CertificationRequestBuilder {
	
	private X500Name subjectName;
    private X500Name certAuthorityName;
    private X509CertificateHolder subjectCert;

    public PendingRequestHolder build() throws NoSuchAlgorithmException, OperatorCreationException, CMPException{
    	
    	validate();
    	
		Provider provider = PlhCMPSystem.getProvider();

        byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCert);

        GeneralName subject = new GeneralName(subjectName);
        GeneralName ca = new GeneralName(certAuthorityName);
        
        PrivateKeyHolder privateKeyHolder = PrivateKeyHolder.getInstance(subjectName);
        
        PrivateKey subjectPrivateKey = privateKeyHolder.getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(subjectCert));
		ContentSigner subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(subjectPrivateKey );
        
        // The initialization request must specify the SubjectPublicKeyInfo, The keyId and the validity
        // of each certificate requested.
        Date notBefore = new Date();
        Date notAfter = DateUtils.addYears(notBefore, 10);
		OptionalValidity optionalValidity = new OptionalValidityHolder(notBefore,notAfter).getOptionalValidity();
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(subjectName)
        	.setIssuer(certAuthorityName)
        	.setPublicKey(subjectCert.getSubjectPublicKeyInfo())
        	.setValidity(optionalValidity).build();
		byte[] txId = UUIDUtils.newUUIDAsBytes();
		ASN1Integer certReqId = new ASN1Integer(new BigInteger(txId));
		Controls controls = null;
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, controls);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(subject, ca)
                                                  .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, certReqMessages))
                                                  .addCMPCertificate(subjectCert)
                                                  .setMessageTime(new Date())
                                                  .setSenderKID(subjectKeyId)
											      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
											      .setTransactionID(txId)
                                                  .build(subjectSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		
		PendingRequestHolder pendingRequestHolder = new PendingRequestHolder();
		pendingRequestHolder.setPkiMessage(pkiMessage);
		
		return pendingRequestHolder;
	}

	public CertificationRequestBuilder withSubjectName(X500Name subjectName) {
		this.subjectName = subjectName;
		return this;
	}

	public CertificationRequestBuilder withCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
		return this;
	}

	public CertificationRequestBuilder withSubjectCert(X509CertificateHolder subjectCert) {
		this.subjectCert = subjectCert;
		return this;
	}

	private void validate() {
		assert subjectName!=null:"Field subjectName can not be null";
		assert certAuthorityName!=null:"Field certAuthorityName can not be null";
		assert subjectCert!=null:"Field subjectCert can not be null";
	}

}
