package org.adorsys.plh.pkix.core.cmp.pollrequest;

import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestData;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class PollRequestBuilder {

	private final BuilderChecker checker = new BuilderChecker(PollReplyValidationPostAction.class);
    public void build(ActionContext actionContext) {
    	checker.checkDirty().checkNull(actionContext);
    	PendingRequestData pendingRequestSData = actionContext.get(PendingRequestData.class);
    	KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
    	checker.checkNull(pendingRequestSData);
        
        PKIMessage pollRepPKIMessage = pendingRequestSData.getPendingRequest().getPollRepMessage();
        GeneralPKIMessage pollRepGeneralPKIMessage = new GeneralPKIMessage(pollRepPKIMessage);
        PKIHeader pollRepPkiHeader = pollRepGeneralPKIMessage.getHeader();
        PollRepContent pollRepContent = PollRepContent.getInstance(pollRepGeneralPKIMessage.getBody().getContent());
		
		DERSequence derSequence = new DERSequence(new DERSequence(pollRepContent.getCertReqId()));
		PollReqContent pollReqContent = PollReqContent.getInstance(derSequence);
	
		ASN1OctetString recipKID = pollRepPKIMessage.getHeader().getRecipKID();
		PrivateKeyEntry privateKeyEntry = null;
		if(recipKID!=null){
			privateKeyEntry = keyStoreWraper.getMessageKeyEntryBySubjectKeyId(recipKID);
		}
		
		if(privateKeyEntry==null){
			GeneralName recipient = pollRepPKIMessage.getHeader().getRecipient();
			if(recipient!=null){
				X500Name subjectName = X500Name.getInstance(recipient.getName());
				privateKeyEntry = keyStoreWraper.getMessageKeyEntryBySubjectName(subjectName);
			}
		}
		
		if(privateKeyEntry==null){
			privateKeyEntry = keyStoreWraper.getAnyMessageKeyEntry();
		}
		
		Certificate certificate = privateKeyEntry.getCertificate();
		X509CertificateHolder subjectCert;
		try {
			subjectCert = new X509CertificateHolder(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
        GeneralName subject = new GeneralName(subjectCert.getSubject());
		ContentSigner subjectSigner;
		try {
			subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
			.setProvider(ProviderUtils.bcProvider).build(privateKeyEntry.getPrivateKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCert);

		ProtectedPKIMessage mainMessage;
		try {
			mainMessage = new ProtectedPKIMessageBuilder(subject, pollRepPkiHeader.getSender())
			                                          .setBody(new PKIBody(PKIBody.TYPE_POLL_REQ, pollReqContent))
			                                          .addCMPCertificate(subjectCert)
			                                          .setMessageTime(new Date())
			                                          .setSenderKID(subjectKeyId)
			                                          .setSenderNonce(UUIDUtils.newUUIDAsBytes())
			                                          .setRecipNonce(pollRepPkiHeader.getSenderNonce().getOctets())
			                                          .setTransactionID(pollRepPkiHeader.getTransactionID().getOctets())
			                                          .build(subjectSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
		
		PKIMessage pollReqPKIMessage = mainMessage.toASN1Structure();
		
		pendingRequestSData.getPendingRequest().setPollReqMessage(pollReqPKIMessage);
	}
}
