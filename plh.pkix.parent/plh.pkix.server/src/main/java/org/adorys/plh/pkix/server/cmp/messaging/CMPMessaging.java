package org.adorys.plh.pkix.server.cmp.messaging;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageConformity;
import org.adorys.plh.pkix.core.cmp.utils.GeneralNameHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.PkiMessageBuilder;
import org.adorys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCert;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
import org.adorys.plh.pkix.server.cmp.messaging.handler.CMPMessagingServerRequestHandler;
import org.adorys.plh.pkix.server.cmp.utils.ErrorCommand;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
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

/**
 * The CMPMessagingServer receives messages and delivers responses.
 * 
 * @author francis
 *
 */
@Path("/messaging")
@Stateless
public class CMPMessaging {

	
//	@PersistenceContext
//	private EntityManager entityManager;
	
	@EJB
	private CMPMessagingServerRequestHandler cmpMessagingServerRequestHandler;

	@EJB
	private EndEntityInitializer endEntityInitializer;
	
	@EJB
	private EndEntityCertRepository endEntityCertRepository;
	
	@EJB
	private CMPRequestDataRepository cmpRequestDataRepository;
	
	@EJB
	private CMPReplyDataRepository cmpReplyDataRepository;

	/**
	 * An end entity is sending a request to another end entity. If the request
	 * is addressed to the server, it replies synchronously, if not the server
	 * sends a poll response to the client.
	 * 
	 * @param pkiMessageBytes
	 * @return
	 */
	@POST
	@Path("/req")
	@Consumes(PlhCMPSystem.PKIX_CMP_STRING)
	@Produces(PlhCMPSystem.PKIX_CMP_STRING)
	public Response cmpRequest(byte[] pkiMessageBytes){

		// Read the data structure sent and extract header
		GeneralPKIMessage generalPKIMessage = new PkiMessageBuilder().withPkiMessageBytes(pkiMessageBytes).build();

		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
		PKIHeader pkiHeader = protectedPKIMessage.getHeader();

		GeneralNameHolder recipientNameHolder = new GeneralNameHolder(pkiHeader.getRecipient());
		X500Name serverX500Name = endEntityInitializer.getServerX500Name();
		GeneralNameHolder senderHolder = new GeneralNameHolder(pkiHeader.getSender());

		// Forward request to server for synchronous response.
		if(serverX500Name.equals(recipientNameHolder.getX500Name()))
			return cmpMessagingServerRequestHandler.handleRequest(generalPKIMessage);

		List<EndEntityCert> serverSignedCerts = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(
				senderHolder.getX500Name(), serverX500Name);
		if(serverSignedCerts.isEmpty())
			return ErrorCommand.error(Status.BAD_REQUEST, "Sender not register with this server.");

		X509CertificateHolder senderCertificate;
		EndEntityCert senderCert = serverSignedCerts.iterator().next();
		try {
			senderCertificate = new X509CertificateHolder(senderCert.getCertificate());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
				
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
		}

		// Store the message for the recipient
		CMPRequestData pkiMessageData = new CMPRequestData();
				
		DERGeneralizedTime messageTime = pkiHeader.getMessageTime();
		if(messageTime!=null)
			try {
				pkiMessageData.setMessageTime(messageTime.getDate());
			} catch (ParseException e) {
				return ErrorCommand.error(Status.BAD_REQUEST, e.getMessage());
			}
		
		pkiMessageData.setPkiMessage(pkiMessageBytes);

		pkiMessageData.setReceptionTime(new Date());
		
		pkiMessageData.setRecipient(recipientNameHolder.getCN());
		pkiMessageData.setSender(senderHolder.getCN());
		
		ASN1OctetString transactionID = pkiHeader.getTransactionID();
		if(transactionID==null)
			return ErrorCommand.error(Status.BAD_REQUEST, "Missing transaction id");
		
		pkiMessageData.setTransactionID(transactionID.toString());

		pkiMessageData.setId(UUID.randomUUID().toString());
		
		cmpRequestDataRepository.create(pkiMessageData);
      
		return returnResponse(transactionID.getOctets(), pkiHeader.getSender(), pkiHeader.getSenderNonce(), pkiHeader.getSenderKID());
	}
	
	/**
	 * This pull request is sent by an end entity to the server, to read it inbox.
	 * 
	 * @param pkiMessageBytes:contains a simple poll request. But signed by the sender.
	 * @return
	 */
	@POST
	@Path("/fetch")
	@Consumes(PlhCMPSystem.PKIX_CMP_STRING)
	public Response cmpFetch(byte[] pkiMessageBytes){

		// Read the data structure sent and extract header
		GeneralPKIMessage generalPKIMessage = new PkiMessageBuilder().withPkiMessageBytes(pkiMessageBytes).build();

		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
		PKIHeader pkiHeader = protectedPKIMessage.getHeader();

		GeneralNameHolder recipientNameHolder = new GeneralNameHolder(pkiHeader.getRecipient());
		X500Name serverX500Name = endEntityInitializer.getServerX500Name();
		GeneralNameHolder senderHolder = new GeneralNameHolder(pkiHeader.getSender());

		if(!serverX500Name.equals(recipientNameHolder.getX500Name()))
			return ErrorCommand.error(Status.BAD_REQUEST, "Request must be sent to server.");

		List<EndEntityCert> serverSignedCerts = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(
				senderHolder.getX500Name(), serverX500Name);
		if(serverSignedCerts.isEmpty())
			return ErrorCommand.error(Status.BAD_REQUEST, "Sender not register with this server.");

		X509CertificateHolder senderCertificate;
		EndEntityCert senderCert = serverSignedCerts.iterator().next();
		try {
			senderCertificate = new X509CertificateHolder(senderCert.getCertificate());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
				
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
		}

		CMPRequestData originalPkiMessageData = cmpRequestDataRepository.findByRecipient(senderHolder.getX500Name());
		if(originalPkiMessageData==null)
			return Response.status(Status.NO_CONTENT).build();
		

		GeneralPKIMessage originalPKIMessage;
		try {
			originalPKIMessage = new GeneralPKIMessage(originalPkiMessageData.getPkiMessage());
		} catch (IOException e) {// Corrupted message, delete it from data source
			cmpRequestDataRepository.remove(originalPkiMessageData);
			return ErrorCommand.error(Status.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		
		PKIHeader originalPkiHeader = originalPKIMessage.getHeader();
		GeneralNameHolder originalPkiHeaader = new GeneralNameHolder(originalPkiHeader.getRecipient());
		
		// verify if sender of the fetch message is receiver of original message.
		if(!senderHolder.getX500Name().equals(originalPkiHeaader.getX500Name()))// wrong receiver
			return Response.status(Status.FORBIDDEN).entity("Requestor not rightful receiver").build();
		
		// return original message.
		Response response = Response.ok(originalPkiMessageData.getPkiMessage(), PlhCMPSystem.PKIX_CMP_STRING).build();

		originalPkiMessageData.setDeliveryTime(new Date());

		cmpRequestDataRepository.merge(originalPkiMessageData);
		
		return response;
	}

	@POST
	@Path("/rep")
	@Consumes(PlhCMPSystem.PKIX_CMP_STRING)
	public Response cmpReply(byte[] pkiMessageBytes){

		// Read the data structure sent and extract header
		GeneralPKIMessage generalPKIMessage = new PkiMessageBuilder().withPkiMessageBytes(pkiMessageBytes).build();

		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
		PKIHeader pkiHeader = protectedPKIMessage.getHeader();

		GeneralNameHolder recipientNameHolder = new GeneralNameHolder(pkiHeader.getRecipient());
		GeneralNameHolder senderHolder = new GeneralNameHolder(pkiHeader.getSender());

		X500Name serverX500Name = endEntityInitializer.getServerX500Name();
		if(serverX500Name.equals(recipientNameHolder.getX500Name()))
			return ErrorCommand.error(Status.BAD_REQUEST, "Reply can not be addressed to serverS.");

		List<EndEntityCert> serverSignedCerts = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(
				senderHolder.getX500Name(), serverX500Name);
		if(serverSignedCerts.isEmpty())
			return ErrorCommand.error(Status.BAD_REQUEST, "Sender not register with this server.");

		X509CertificateHolder senderCertificate;
		EndEntityCert senderCert = serverSignedCerts.iterator().next();
		try {
			senderCertificate = new X509CertificateHolder(senderCert.getCertificate());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
				
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
		}

		// Store the message for the recipient
		CMPReplyData cmpReplyData = new CMPReplyData();

		DERGeneralizedTime messageTime = pkiHeader.getMessageTime();
		if(messageTime!=null)
			try {
				cmpReplyData.setMessageTime(messageTime.getDate());
			} catch (ParseException e) {
				return ErrorCommand.error(Status.BAD_REQUEST, e.getMessage());
			}
		
		cmpReplyData.setPkiMessage(pkiMessageBytes);

		cmpReplyData.setReceptionTime(new Date());
		
		cmpReplyData.setRecipient(recipientNameHolder.getCN());
		cmpReplyData.setSender(senderHolder.getCN());
		
		ASN1OctetString transactionID = pkiHeader.getTransactionID();
		if(transactionID==null)
			return ErrorCommand.error(Status.BAD_REQUEST, "Missing transaction id");

		cmpReplyData.setTransactionID(transactionID.toString());
		
		// store
		cmpReplyData.setId(UUID.randomUUID().toString());
		cmpReplyDataRepository.create(cmpReplyData);
		
		return Response.ok().build();
	}

	private Response returnResponse(byte[] transactionId, GeneralName receivingSender, 
			ASN1OctetString senderNonce, ASN1OctetString senderKID){
		Provider provider = PlhCMPSystem.getProvider();
        ContentSigner senderSigner;
        try {
			senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(endEntityInitializer.getServerPrivateKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}
		X509CertificateHolder senderCert = endEntityInitializer.getServerCertificate();
        ASN1Integer certReqId = new ASN1Integer(new BigInteger(transactionId));
        ASN1Integer checkAfter = new ASN1Integer(60*60);
        PKIFreeText reason = new PKIFreeText("Asynchronous");
		ASN1Encodable[] array = new ASN1Encodable[]{certReqId, checkAfter, reason};
		DERSequence derSequence = new DERSequence(array );
        PollRepContent pollRepContent = PollRepContent.getInstance(derSequence);        
        GeneralName serverGeneralName = new GeneralName(senderCert.getSubject());
        ProtectedPKIMessage mainMessage;

		try {
			ProtectedPKIMessageBuilder protectedPKIMessageBuilder = new ProtectedPKIMessageBuilder(serverGeneralName, receivingSender)
			                                          .setBody(new PKIBody(PKIBody.TYPE_POLL_REP, 
			                                        		  pollRepContent))
			                                          .addCMPCertificate(senderCert)
			                                          .setMessageTime(new Date())
			                                          .setSenderKID(KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCert))
			                                          .setSenderNonce(UUID.randomUUID().toString().getBytes())
			                                          .setTransactionID(transactionId);
			if(senderNonce!=null)
				protectedPKIMessageBuilder = protectedPKIMessageBuilder.setRecipNonce(senderNonce.getOctets());
			if(senderKID!=null)
				protectedPKIMessageBuilder = protectedPKIMessageBuilder.setRecipKID(senderKID.getOctets());
			mainMessage = protectedPKIMessageBuilder.build(senderSigner);
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
