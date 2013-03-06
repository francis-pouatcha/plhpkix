package org.adorsys.plh.pkix.core.cmp.registration;

import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;
import java.util.Random;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;

public class RegistrationRequestInitActionExecutor {

	private static Random rnd = new Random();
	
	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestInitActionExecutor.class);
	public ProcessingResults<OutgoingRegistrationRequestData> build(PrivateKeyEntry privateKeyEntry) 
	{
		checker.checkDirty();
		
		X509CertificateHolder subjectCertificate = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
		X500Name subjectDN = X500NameHelper.readSubjectDN(subjectCertificate);
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(subjectDN)
        	.setIssuer(subjectDN).build();

		ContentSigner senderSigner = V3CertificateUtils.getContentSigner(privateKeyEntry.getPrivateKey(),"MD5WithRSAEncryption");

		BigInteger probablePrime = BigInteger.probablePrime(9, rnd);
		ASN1Integer certReqId = new ASN1Integer(probablePrime);
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, null);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        byte[] publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(subjectCertificate);

        ProcessingResults<OutgoingRegistrationRequestData> processingResults = new ProcessingResults<OutgoingRegistrationRequestData>();
        ProtectedPKIMessage mainMessage;
		try {
			mainMessage = new ProtectedPKIMessageBuilder(new GeneralName(subjectDN), new GeneralName(subjectDN))
			                                          .setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages))
			                                          .addCMPCertificate(subjectCertificate)
			                                          .setMessageTime(new Date())
			                                          .setSenderKID(publicKeyIdentifier)
			                                          .setRecipKID(publicKeyIdentifier)
												      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
												      .setTransactionID(UUIDUtils.newUUIDAsBytes())
			                                          .build(senderSigner);
		} catch (CMPException e) {
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_generalCMPException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		OutgoingRequest certificationRequest = 
				new OutgoingRequest(certReqId, pkiMessage, new DERGeneralizedTime(new Date()));
		OutgoingRegistrationRequestData registrationRequestData = new OutgoingRegistrationRequestData(certificationRequest);
		processingResults.setReturnValue(registrationRequestData);
		return processingResults;
	}
}
