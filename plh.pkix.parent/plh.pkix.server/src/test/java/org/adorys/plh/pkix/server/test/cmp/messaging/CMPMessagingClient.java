package org.adorys.plh.pkix.server.test.cmp.messaging;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.server.cmp.core.PendingRequestHolder;
import org.adorys.plh.pkix.server.cmp.core.PlhCMPSystem;
import org.adorys.plh.pkix.server.cmp.core.certann.CertificateAnnouncementBuilder;
import org.adorys.plh.pkix.server.cmp.core.certann.CertificateAnnouncementHolder;
import org.adorys.plh.pkix.server.cmp.core.certrequest.CertificationReplyProcessor;
import org.adorys.plh.pkix.server.cmp.core.certrequest.CertificationRequestBuilder;
import org.adorys.plh.pkix.server.cmp.core.certrequest.CertificationRequestProcessor;
import org.adorys.plh.pkix.server.cmp.core.fetch.FetchRequestTypesValue;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationRequestBuilder;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationRequestHolder;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationResponseProcessor;
import org.adorys.plh.pkix.server.cmp.core.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.server.cmp.core.message.PkiMessageConformity;
import org.adorys.plh.pkix.server.cmp.core.pollrequest.PollReplyProcessor;
import org.adorys.plh.pkix.server.cmp.core.pollrequest.PollRequestBuilder;
import org.adorys.plh.pkix.server.cmp.core.stores.CertificateStore;
import org.adorys.plh.pkix.server.cmp.core.stores.PendingCertAnn;
import org.adorys.plh.pkix.server.cmp.core.stores.PendingPollRequest;
import org.adorys.plh.pkix.server.cmp.core.stores.PendingResponses;
import org.adorys.plh.pkix.server.cmp.core.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.server.cmp.core.utils.ErrorCommand;
import org.adorys.plh.pkix.server.cmp.core.utils.GeneralNameHolder;
import org.adorys.plh.pkix.server.cmp.core.utils.KeyIdUtils;
import org.adorys.plh.pkix.server.cmp.core.utils.RequestVerifier;
import org.adorys.plh.pkix.server.cmp.core.utils.UUIDUtils;
import org.adorys.plh.pkix.server.cmp.core.utils.X509CertificateHolderCollection;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ByteArrayEntity;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CMPMessagingClient {
	private static final String REQSUFFIX = "/req";
	private static final String FETCHSUFFIX = "/fetch";
	private static final String REPSUFFIX = "/rep";

	private X500Name endEntityName;
	private String addressPrefix;

	public void initKeyPair() throws NoSuchAlgorithmException {
		new KeyPairBuilder().withEndEntityName(endEntityName).build();
	}

	public Response initialize(X500Name certSigner)
			throws OperatorCreationException, GeneralSecurityException,
			IOException, CertException, CMPException {

		validate();

		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder
				.getInstance(endEntityName);
		PrivateKey privateKey = privateKeyHolder.getPrivateKey(KeyIdUtils
				.getSubjectKeyIdentifierAsOctetString(senderCertificate));
		InitializationRequestHolder initializationRequestHolder = new InitializationRequestBuilder()
				.withEndEntityName(endEntityName)
				.withRecipientX500Name(
						new X500Name(PlhCMPSystem.getServerName()))
				.build(privateKey, senderCertificate);

		PKIMessage pkiMessage = initializationRequestHolder.getPkiMessage();

		HttpResponse sendingRsponse = Request
				.Post(addressPrefix + REQSUFFIX)
				.body(new ByteArrayEntity(pkiMessage.getEncoded(),
						PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
				.returnResponse();

		if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK
				.getStatusCode())
			return Response
					.status(sendingRsponse.getStatusLine().getStatusCode())
					.entity(sendingRsponse.getEntity()).build();

		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
				IOUtils.toByteArray(inputStream));

		// Check message conformity
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
				.check(generalPKIMessage);

		// Verify the response. In the very first case, the certificate used to
		// sign the response will not be in the store.
		X509CertificateHolder responseSenderCertificate;
		GeneralNameHolder initialRecipientHolder = new GeneralNameHolder(initializationRequestHolder.getPkiMessage().getHeader().getRecipient());
		GeneralNameHolder senderHolder = new GeneralNameHolder(protectedPKIMessage.getHeader().getSender());
		X500Name serverX500Name = new X500Name(PlhCMPSystem.getServerName());
		
		// response sender is either recipient or server
		if(!senderHolder.getX500Name().equals(initialRecipientHolder.getX500Name()) && !senderHolder.getX500Name().equals(serverX500Name))
			return ErrorCommand.error(Status.BAD_REQUEST,"Response from wrong sender");
			
		responseSenderCertificate = certificateStore.getCertificate(initialRecipientHolder.getX500Name());

		if (responseSenderCertificate == null && senderHolder.getX500Name().equals(serverX500Name)) {
			responseSenderCertificate = new X509CertificateHolderCollection(
					protectedPKIMessage.getCertificates())
					.findBySubjectName(senderHolder.getX500Name());
		}


		if (responseSenderCertificate == null)
			return ErrorCommand.error(Status.BAD_REQUEST,
					"Missing server certificate");

		Response verifiedRequest = RequestVerifier.verifyRequest(
				protectedPKIMessage, responseSenderCertificate);
		if (verifiedRequest.getStatus() != Status.OK.getStatusCode())
			return verifiedRequest;

		CertTemplate certTemplate = initializationRequestHolder
				.getCertTemplate();
		new InitializationResponseProcessor().setCertificateStore(
				certificateStore).process(certTemplate, protectedPKIMessage);

		X509CertificateHolder certificate = certificateStore.getCertificate(
				certTemplate.getSubject(), certTemplate.getIssuer());
		if (certificate == null)
			return ErrorCommand.error(Status.CONFLICT,
					"Missing server certificate");

		return Response.ok().build();

	}

	public Response requestCertificate(X500Name certAuthorityName)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, ClientProtocolException, IOException {

		validate();

		CertificateStore certificateStore = CertificateStore
				.getInstance(endEntityName);
		X509CertificateHolder subjectCert = certificateStore
				.getCertificate(endEntityName);

		PendingRequestHolder certificationRequestHolder = new CertificationRequestBuilder()
				.withCertAuthorityName(certAuthorityName)
				.withSubjectName(endEntityName)
				.withSubjectCert(subjectCert)
				.build();

		PKIMessage pkiMessage = certificationRequestHolder.getPkiMessage();

		HttpResponse sendingRsponse = Request
				.Post(addressPrefix + REQSUFFIX)
				.body(new ByteArrayEntity(pkiMessage.getEncoded(),
						PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
				.returnResponse();
		
		
		if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK
				.getStatusCode())
			return Response
					.status(sendingRsponse.getStatusLine().getStatusCode())
					.entity(sendingRsponse.getEntity()).build();

		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
				IOUtils.toByteArray(inputStream));

		// Check message conformity
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
				.check(generalPKIMessage);

		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder
				.getInstance(endEntityName);
		PrivateKey privateKey = privateKeyHolder.getPrivateKey(KeyIdUtils
				.getSubjectKeyIdentifierAsOctetString(subjectCert));

		switch (protectedPKIMessage.getBody().getType()) {
		case PKIBody.TYPE_POLL_REP:
			return new PollReplyProcessor()
					.withPendingRequestHolder(certificationRequestHolder)
					.withEndEntityName(endEntityName)
					.process(generalPKIMessage);
		case PKIBody.TYPE_CERT_REP:
			return new CertificationReplyProcessor()
					.withEndEntityName(endEntityName)
					.withSubjectPrivateKey(privateKey)
					.process(generalPKIMessage);
		default:
			return ErrorCommand.error(Status.NOT_ACCEPTABLE,
					"Unexpected response type; "
							+ protectedPKIMessage.getBody().getType());
		}
	}

	public Response pollRequests(X500Name certSigner)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, IOException {

		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		PendingPollRequest pendingPollRequest = PendingPollRequest
				.getInstance(endEntityName);
		List<PendingRequestHolder> pollRequests = pendingPollRequest
				.loadPollRequests();
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder
				.getInstance(endEntityName);
		for (PendingRequestHolder pendingRequestHolder : pollRequests) {
			new PollRequestBuilder()
					.withPrivateKeyHolder(privateKeyHolder)
					.withSubjectName(endEntityName)
					.withSubjectCert(senderCertificate)
					.build(pendingRequestHolder);

			PKIMessage pkiMessage = pendingRequestHolder.getPollReqMessage();

			HttpResponse sendingRsponse = Request
					.Post(addressPrefix + REQSUFFIX)
					.body(new ByteArrayEntity(pkiMessage.getEncoded(),
							PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
					.returnResponse();

			if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK
					.getStatusCode())
				return Response
						.status(sendingRsponse.getStatusLine().getStatusCode())
						.entity(sendingRsponse.getEntity()).build();

			InputStream inputStream = sendingRsponse.getEntity().getContent();
			GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
					IOUtils.toByteArray(inputStream));

			// Check message conformity
			ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
					.check(generalPKIMessage);


			PrivateKey privateKey = privateKeyHolder.getPrivateKey(KeyIdUtils
					.getSubjectKeyIdentifierAsOctetString(senderCertificate));

			switch (protectedPKIMessage.getBody().getType()) {
			case PKIBody.TYPE_POLL_REP:
				new PollReplyProcessor()
						.withPendingRequestHolder(pendingRequestHolder)
						.withEndEntityName(endEntityName)
						.process(generalPKIMessage);
				break;
			case PKIBody.TYPE_CERT_REP:
				new CertificationReplyProcessor()
						.withEndEntityName(endEntityName)
						.withSubjectPrivateKey(privateKey)
						.process(generalPKIMessage);
				break;
			default:
				return ErrorCommand.error(Status.NOT_ACCEPTABLE,
						"Unexpected response type; "
								+ protectedPKIMessage.getBody().getType());
			}
		}
		return Response.ok().build();
	}
	
	public Response fetchRequests(int iteration, X500Name certSigner) throws OperatorCreationException, CMPException, ClientProtocolException, IOException{

		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		InfoTypeAndValue itv = new InfoTypeAndValue(new FetchRequestTypesValue());
		GenMsgContent genMsgContent = new GenMsgContent(itv);
		
		X500Name serverX500Name = new X500Name(PlhCMPSystem.getServerName());
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder
				.getInstance(endEntityName);
        PrivateKey subjectPrivateKey = privateKeyHolder.getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(senderCertificate));
		ContentSigner subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(PlhCMPSystem.getProvider()).build(subjectPrivateKey );

		byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCertificate);
		ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(new GeneralName(endEntityName), new GeneralName(serverX500Name))
	        .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, genMsgContent))
	        .addCMPCertificate(senderCertificate)
	        .setMessageTime(new Date())
	        .setSenderKID(subjectKeyId)
	        .setSenderNonce(UUIDUtils.newUUIDAsBytes())
	        .setTransactionID(UUIDUtils.newUUIDAsBytes())
	        .build(subjectSigner);
        
        PKIMessage pkiMessage = mainMessage.toASN1Structure();

		HttpResponse sendingRsponse = Request
				.Post(addressPrefix + FETCHSUFFIX)
				.body(new ByteArrayEntity(pkiMessage.getEncoded(),
						PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
				.returnResponse();

		if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK
				.getStatusCode())
			return Response
					.status(sendingRsponse.getStatusLine().getStatusCode())
					.entity(sendingRsponse.getEntity()).build();

		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
				IOUtils.toByteArray(inputStream));

		// Check message conformity
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
				.check(generalPKIMessage);

		switch (protectedPKIMessage.getBody().getType()) {
			case PKIBody.TYPE_CERT_REQ:
				new CertificationRequestProcessor()
					.setIssuerKeyId(subjectKeyId)
					.setIssuerName(endEntityName)
					.setIssuerPrivateKey(subjectPrivateKey)
					.setIssuerX509CertificateHolder(senderCertificate)
					.process(generalPKIMessage);
				break;
			default:
				return ErrorCommand.error(Status.NOT_ACCEPTABLE,
						"Unexpected request type; "
							+ protectedPKIMessage.getBody().getType());
		}
		iteration=iteration+1;
		if(iteration>10)return Response.ok().build();
		
		return fetchRequests(iteration, certSigner);
	}
	
	public Response sendResponses(X500Name certSigner) throws ClientProtocolException, IOException{
		
		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		PendingResponses pendingResponses = PendingResponses.getInstance(endEntityName);
		PKIMessage pkiMessage = pendingResponses.getNext();
		while(pkiMessage!=null){
			
			HttpResponse sendingRsponse = Request
					.Post(addressPrefix + REPSUFFIX)
					.body(new ByteArrayEntity(pkiMessage.getEncoded(),
							PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
					.returnResponse();

			if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK
					.getStatusCode())
				return Response
						.status(sendingRsponse.getStatusLine().getStatusCode())
						.entity(sendingRsponse.getEntity()).build();

			
			pkiMessage = pendingResponses.getNext();
		}
		
		return Response.ok().build();
	}

	public Response announceCertificates() throws ClientProtocolException, IOException{

//		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
//		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
//		if(senderCertificate==null)
//			throw new IllegalStateException("No certificate with signer");

		PendingCertAnn pendingCertAnn = PendingCertAnn.getInstance(endEntityName);
		X509CertificateHolder certificateHolder = pendingCertAnn.getNext();

		while(certificateHolder!=null){
			CertificateAnnouncementHolder certificateAnnouncementHolder = new CertificateAnnouncementBuilder()
				.withSubjectName(endEntityName)
				.withSubjectCertificate(certificateHolder)
				.build();

			PKIMessage pkiMessage = certificateAnnouncementHolder.getPkiMessage();
			HttpResponse sendingRsponse = Request
					.Post(addressPrefix + REQSUFFIX)
					.body(new ByteArrayEntity(pkiMessage.getEncoded(),
							PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute()
					.returnResponse();

			if (sendingRsponse.getStatusLine().getStatusCode() != Status.OK.getStatusCode())
				return Response
						.status(sendingRsponse.getStatusLine().getStatusCode())
						.entity(sendingRsponse.getEntity()).build();
			
			certificateHolder = pendingCertAnn.getNext();
		}

		return Response.ok().build();
	}
	
	public CMPMessagingClient withClientName(X500Name clientName) {
		this.endEntityName = clientName;
		return this;
	}

	public CMPMessagingClient withAddressPrefix(String addressPrefix) {
		this.addressPrefix = addressPrefix;
		return this;
	}

	private void validate() {
		assert endEntityName != null : "Field clientName can not be null";
		assert addressPrefix != null : "Field addressPrefix can not be null";
	}
}
