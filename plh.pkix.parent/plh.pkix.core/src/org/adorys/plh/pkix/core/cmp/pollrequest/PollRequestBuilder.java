package org.adorys.plh.pkix.core.cmp.pollrequest;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
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

	private X500Name subjectName;
    private X509CertificateHolder subjectCert;
    private PrivateKeyHolder privateKeyHolder;

    public void build(final PendingRequestHolder pendingRequestHolder) throws NoSuchAlgorithmException, OperatorCreationException, CMPException{
    	
		assert pendingRequestHolder!=null:"Field pendingRequestHolder can not be null";

		validate();
    	
		Provider provider = PlhCMPSystem.getProvider();
        
        PKIMessage pollRepPKIMessage = pendingRequestHolder.getPollRepMessage();
        GeneralPKIMessage pollRepGeneralPKIMessage = new GeneralPKIMessage(pollRepPKIMessage);
        PKIHeader pollRepPkiHeader = pollRepGeneralPKIMessage.getHeader();
        PollRepContent pollRepContent = PollRepContent.getInstance(pollRepGeneralPKIMessage.getBody().getContent());
		
//		ASN1Encodable[] array = new ASN1Encodable[]{pollRepContent.getCertReqId()};
//		DERSequence derSequence = new DERSequence(array);
		DERSequence derSequence = new DERSequence(new DERSequence(pollRepContent.getCertReqId()));
		PollReqContent pollReqContent = PollReqContent.getInstance(derSequence);
		
        GeneralName subject = new GeneralName(subjectName);
        PrivateKey subjectPrivateKey = privateKeyHolder.getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(subjectCert));
		ContentSigner subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(subjectPrivateKey );

		byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCert);

		ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(subject, pollRepPkiHeader.getSender())
                                                  .setBody(new PKIBody(PKIBody.TYPE_POLL_REQ, pollReqContent))
                                                  .addCMPCertificate(subjectCert)
                                                  .setMessageTime(new Date())
                                                  .setSenderKID(subjectKeyId)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setRecipNonce(pollRepPkiHeader.getSenderNonce().getOctets())
                                                  .setTransactionID(pollRepPkiHeader.getTransactionID().getOctets())
                                                  .build(subjectSigner);
		PKIMessage pollReqPKIMessage = mainMessage.toASN1Structure();
		pendingRequestHolder.setPollReqMessage(pollReqPKIMessage);
	}

	public PollRequestBuilder withSubjectName(X500Name subjectName) {
		this.subjectName = subjectName;
		return this;
	}

	public PollRequestBuilder withSubjectCert(X509CertificateHolder subjectCert) {
		this.subjectCert = subjectCert;
		return this;
	}

	public PollRequestBuilder withPrivateKeyHolder(PrivateKeyHolder privateKeyHolder) {
		this.privateKeyHolder = privateKeyHolder;
		return this;
	}

	private void validate() {
		assert subjectName!=null:"Field subjectName can not be null";
		assert privateKeyHolder!=null:"Field privateKeyHolder can not be null";
		assert subjectCert!=null:"Field subjectCert can not be null";
	}
}
