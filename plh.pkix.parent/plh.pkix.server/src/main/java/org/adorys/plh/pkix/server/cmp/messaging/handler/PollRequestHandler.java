package org.adorys.plh.pkix.server.cmp.messaging.handler;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;
import java.util.Arrays;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.utils.GeneralNameHolder;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
import org.adorys.plh.pkix.server.cmp.messaging.CMPReplyData;
import org.adorys.plh.pkix.server.cmp.messaging.CMPReplyDataRepository;
import org.adorys.plh.pkix.server.cmp.messaging.CMPRequestData;
import org.adorys.plh.pkix.server.cmp.messaging.CMPRequestDataRepository;
import org.adorys.plh.pkix.server.cmp.utils.ErrorCommand;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@Stateless
public class PollRequestHandler extends CMPRequestHandler {

	@EJB
	private EndEntityCertRepository endEntityCertRepository;

	@EJB
	private EndEntityInitializer endEntityInitializer;
	
	@EJB
	private CMPReplyDataRepository cmpReplyDataRepository;
	
	@EJB
	private CMPRequestDataRepository cmpRequestDataRepository;

	@Override
	public Response handleRequest(GeneralPKIMessage pkiMessage) {

		PKIBody pkiBody = pkiMessage.getBody();
		PKIHeader pkiHeader = pkiMessage.getHeader();
		PollReqContent pollReqContent = PollReqContent.getInstance(pkiBody.getContent());
		ASN1Integer[][] certReqIds = pollReqContent.getCertReqIds();
		
		ASN1OctetString transactionID = pkiHeader.getTransactionID();
		
		ASN1Integer certReqId = certReqIds[0][0];
		BigInteger certReqIdasBigInt = certReqId.getValue();
		
		if(!Arrays.equals(certReqIdasBigInt.toByteArray(), transactionID.getOctets()))
			return ErrorCommand.error(Status.BAD_REQUEST, "TransactionId and certRequestIdmust be identical");
		
		// The sender of this poll request is the sender of the original message.
		// The receiver the server (not the receiver of the original message)
		GeneralNameHolder senderIsRecipientOfReplyHolder = new GeneralNameHolder(pkiHeader.getSender());
		
		// find the requested reply message
		CMPReplyData cmpReplyData = cmpReplyDataRepository.findByTransactionIdAndRecipient(transactionID, senderIsRecipientOfReplyHolder.getX500Name());

		// check if original message
		CMPRequestData cmpRequestData = cmpRequestDataRepository.findByTransactionIdAndSender(transactionID, senderIsRecipientOfReplyHolder.getX500Name());
		
		// load original request. This request will only be deleted when 
		if(cmpReplyData==null){ // Either response not yet available of has never existed.
			if(cmpRequestData==null){
				// if associated request does not exist, reply might have been sent already
				// or the associated request has never existed
				return ErrorCommand.error(Status.NO_CONTENT, "No transaction with associated request id");
			} else {
				if(cmpRequestData.getDeliveryTime()!=null){
					// Message has been delivered. But response hasn't come back yet
					ASN1Integer checkAfter = new ASN1Integer(60);
					returnResponse(transactionID, certReqId, checkAfter, pkiHeader);
				} else {
					// message hasn't been delivered yet
					ASN1Integer checkAfter = new ASN1Integer(60*60);
					returnResponse(transactionID, certReqId, checkAfter, pkiHeader);
				}
			}
		} else {
			if(cmpRequestData!=null){
				cmpRequestDataRepository.remove(cmpRequestData);
			}
			cmpReplyDataRepository.remove(cmpReplyData);
		}

		return Response.ok(cmpReplyData.getPkiMessage(),
				PlhCMPSystem.PKIX_CMP_STRING).build();
	}

	private Response returnResponse(ASN1OctetString transactionID, 
			ASN1Integer certReqId, ASN1Integer checkAfter, PKIHeader pkiHeader){
		
		Provider provider = PlhCMPSystem.getProvider();
        ContentSigner senderSigner;
        try {
			senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
				.setProvider(provider).build(endEntityInitializer.getServerPrivateKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}
		
        X509CertificateHolder senderCert = endEntityInitializer.getServerCertificate();
        
        PKIFreeText reason = new PKIFreeText("Not Ready");
		ASN1Encodable[] array = new ASN1Encodable[]{certReqId, checkAfter, reason};
		DERSequence derSequence = new DERSequence(array );
        PollRepContent pollRepContent = PollRepContent.getInstance(derSequence);        
        GeneralName serverGeneralName = new GeneralName(senderCert.getSubject());
        
        ProtectedPKIMessage mainMessage;
        
		try {
			mainMessage = 
				new ProtectedPKIMessageBuilder(serverGeneralName, pkiHeader.getSender())
				.setBody(new PKIBody(PKIBody.TYPE_POLL_REP, pollRepContent))
				.addCMPCertificate(senderCert)
				.setMessageTime(new Date())
			    .setSenderKID(endEntityInitializer.getServerKeyId())
			    .setSenderNonce(UUIDUtils.newUUIDAsBytes())
			    .setRecipNonce(pkiHeader.getSenderNonce().getOctets())
			    .setRecipKID(pkiHeader.getSenderKID().getOctets())
			    .setTransactionID(pkiHeader.getTransactionID().getOctets())
			    .build(senderSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
		
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		
		try {
			return Response.ok(pkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_STRING).build();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}
