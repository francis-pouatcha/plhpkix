package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Date;
import java.util.Random;

import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
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

public class InitializationRequestBuilder {
	
	private X500Name endEntityName;
    private X500Name recipientX500Name;
	
	public InitializationRequestHolder build(PrivateKey privateKey, X509CertificateHolder certificate) throws NoSuchAlgorithmException, OperatorCreationException, CMPException{

        // The initialization request must specify the SubjectPublicKeyInfo, The keyId and the validity
        // of each certificate requested.
		OptionalValidity optionalValidity = new OptionalValidityHolder(
				DateUtils.addYears(new Date(), -10),DateUtils.addYears(new Date(), 10)).getOptionalValidity();
		
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(recipientX500Name)
        	.setIssuer(recipientX500Name)
        	.setValidity(optionalValidity).build();

		Provider provider = ProviderUtils.bcProvider;
		ContentSigner senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(privateKey);
		
		ASN1Integer certReqId = new ASN1Integer(new Random().nextInt());
		
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, null);
		
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(new GeneralName(endEntityName), new GeneralName(recipientX500Name))
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages))
                                                  .addCMPCertificate(certificate)
                                                  .setMessageTime(new Date())
                                                  .setSenderKID(KeyIdUtils.getSubjectKeyIdentifierAsByteString(certificate))
											      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
											      .setTransactionID(UUIDUtils.newUUIDAsBytes())
                                                  .build(senderSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		
		return new InitializationRequestHolder(pkiMessage, certTemplate);
	}

	public InitializationRequestBuilder withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public InitializationRequestBuilder withRecipientX500Name(X500Name recipientX500Name) {
		this.recipientX500Name = recipientX500Name;
		return this;
	}
}
