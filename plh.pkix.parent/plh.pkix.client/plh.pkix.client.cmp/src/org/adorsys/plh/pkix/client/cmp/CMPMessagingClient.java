package org.adorsys.plh.pkix.client.cmp;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.cmp.certann.CertificateAnnouncementBuilder;
import org.adorsys.plh.pkix.core.cmp.certann.CertificateAnnouncementHolder;
import org.adorsys.plh.pkix.core.cmp.certrequest.ca.CertificationRequestValidationProcessor;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationReplyValidationProcessor;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestInitActionExecutor;
import org.adorsys.plh.pkix.core.cmp.fetch.FetchRequestTypesValue;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestBuilder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestHolder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationResponseValidationActionProcessor;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageConformity;
import org.adorsys.plh.pkix.core.cmp.pollrequest.PollReplyValidationActionProcessor;
import org.adorsys.plh.pkix.core.cmp.pollrequest.PollRequestBuilder;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncements2;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.PendingResponses2;
import org.adorsys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.adorsys.plh.pkix.core.utils.GeneralNameHolder;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.X509CertificateHolderCollection;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
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

	private final X500Name endEntityName;
	private final String addressPrefix;
	private final PrivateKeyHolder privateKeyHolder;
	private final CertificateStore certificateStore;
	private final PendingRequests pendingPollRequest;
	private final PendingCertAnnouncements2 pendingCertAnns;
	private final PendingResponses2 pendingResponses;
	
	public CMPMessagingClient(X500Name endEntityName, String addressPrefix,
			PrivateKeyHolder privateKeyHolder,
			CertificateStore certificateStore,
			PendingRequests pendingPollRequest,
			PendingCertAnnouncements2 pendingCertAnns, PendingResponses2 pendingResponses) {
		super();
		this.endEntityName = endEntityName;
		this.addressPrefix = addressPrefix;
		this.privateKeyHolder = privateKeyHolder;
		this.certificateStore = certificateStore;
		this.pendingPollRequest = pendingPollRequest;
		this.pendingCertAnns = pendingCertAnns;
		this.pendingResponses = pendingResponses;
	}

	public void initKeyPair() {
		new KeyPairBuilder()
			.withEndEntityName(endEntityName)
			.withPrivateKeyHolder(privateKeyHolder)
			.withCertificateStore(certificateStore)
			.build();
	}

	public HttpResponse initialize(X500Name certSigner)
			throws OperatorCreationException, GeneralSecurityException,
			IOException, CertException, CMPException {

		validate();
				
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		PrivateKey privateKey = privateKeyHolder.getPrivateKey(senderCertificate);
		InitializationRequestHolder initializationRequestHolder = new InitializationRequestBuilder()
				.withEndEntityName(endEntityName)
				.withRecipientX500Name(PlhCMPSystem.getServerName())
				.build(privateKey, senderCertificate);

		PKIMessage pkiMessage = initializationRequestHolder.getPkiMessage();

		HttpClient httpclient = new DefaultHttpClient();
		HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
		HttpPost httpPost = new HttpPost(addressPrefix + REQSUFFIX);
		httpPost.setEntity(entity);
		httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
		HttpResponse sendingRsponse = httpclient.execute(httpPost);

		if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
			return sendingRsponse;

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
		X500Name serverX500Name = PlhCMPSystem.getServerName();
		
		// response sender is either recipient or server
		if(!senderHolder.getX500Name().equals(initialRecipientHolder.getX500Name()) && !senderHolder.getX500Name().equals(serverX500Name))
			return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,"Response from wrong sender");
			
		responseSenderCertificate = certificateStore.getCertificate(initialRecipientHolder.getX500Name());

		if (responseSenderCertificate == null && senderHolder.getX500Name().equals(serverX500Name)) {
			responseSenderCertificate = new X509CertificateHolderCollection(
					protectedPKIMessage.getCertificates())
					.findBySubjectName(senderHolder.getX500Name());
		}


		if (responseSenderCertificate == null)
			return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
					"Missing server certificate");

//		Response verifiedRequest = RequestVerifier.verifyRequest(
//				protectedPKIMessage, responseSenderCertificate);
//		if (verifiedRequest.getStatus() != HttpStatus.SC_OK)
//			return verifiedRequest;

		CertTemplate certTemplate = initializationRequestHolder
				.getCertTemplate();
		new InitializationResponseValidationActionProcessor().setCertificateStore(
				certificateStore).process(certTemplate, protectedPKIMessage);

		X509CertificateHolder certificate = certificateStore.getCertificate(
				certTemplate.getSubject(), certTemplate.getIssuer());
		if (certificate == null)
			return ResponseFactory.create(HttpStatus.SC_CONFLICT,
					"Missing server certificate");

		return ResponseFactory.create(HttpStatus.SC_OK, null);

	}

	public HttpResponse requestCertificate(X500Name certAuthorityName)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, ClientProtocolException, IOException {

		validate();
		X509CertificateHolder subjectCert = certificateStore
				.getCertificate(endEntityName);

		PendingRequest certificationRequestHolder = new CertificationRequestInitActionExecutor()
				.withCertAuthorityName(certAuthorityName)
				.withSubjectName(endEntityName)
				.withSubjectCert(subjectCert)
				.withPrivateKeyHolder(privateKeyHolder)
				.build();

		PKIMessage pkiMessage = certificationRequestHolder.getPkiMessage();

		HttpClient httpclient = new DefaultHttpClient();
		HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
		HttpPost httpPost = new HttpPost(addressPrefix + REQSUFFIX);
		httpPost.setEntity(entity);
		httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
		HttpResponse sendingRsponse = httpclient.execute(httpPost);

		if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
			return sendingRsponse;

		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
				IOUtils.toByteArray(inputStream));

		// Check message conformity
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
				.check(generalPKIMessage);

		PrivateKey privateKey = privateKeyHolder.getPrivateKey(subjectCert);

		switch (protectedPKIMessage.getBody().getType()) {
		case PKIBody.TYPE_POLL_REP:
			return new PollReplyValidationActionProcessor()
					.withPendingRequestHolder(certificationRequestHolder)
					.withEndEntityName(endEntityName)
					.withPendingPollRequest(pendingPollRequest)
					.withCertificateStore(certificateStore)
					.process0(generalPKIMessage);
		case PKIBody.TYPE_CERT_REP:
			return new CertificationReplyValidationProcessor()
					.withEndEntityName(endEntityName)
					.withSubjectPrivateKey(privateKey)
					.withCertificateStore(certificateStore)
					.withPendingCertAnns(pendingCertAnns)
					.withPendingPollRequest(pendingPollRequest)
					.process1(generalPKIMessage);
		default:
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE,
					"Unexpected response type; "
							+ protectedPKIMessage.getBody().getType());
		}
	}

	public HttpResponse pollRequests(X500Name certSigner)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, IOException {

		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		List<PendingRequest> pollRequests = pendingPollRequest
				.loadPollRequests();

		for (PendingRequest pendingRequestHolder : pollRequests) {
			new PollRequestBuilder()
					.withPrivateKeyHolder(privateKeyHolder)
					.withSubjectName(endEntityName)
					.withSubjectCert(senderCertificate)
					.build(pendingRequestHolder);

			PKIMessage pkiMessage = pendingRequestHolder.getPollReqMessage();

			HttpClient httpclient = new DefaultHttpClient();
			HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
			HttpPost httpPost = new HttpPost(addressPrefix + REQSUFFIX);
			httpPost.setEntity(entity);
			httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
			HttpResponse sendingRsponse = httpclient.execute(httpPost);

			if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
				return sendingRsponse;

			InputStream inputStream = sendingRsponse.getEntity().getContent();
			GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(
					IOUtils.toByteArray(inputStream));

			// Check message conformity
			ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
					.check(generalPKIMessage);


			PrivateKey privateKey = privateKeyHolder.getPrivateKey(senderCertificate);

			switch (protectedPKIMessage.getBody().getType()) {
			case PKIBody.TYPE_POLL_REP:
				new PollReplyValidationActionProcessor()
						.withPendingRequestHolder(pendingRequestHolder)
						.withEndEntityName(endEntityName)
						.withPendingPollRequest(pendingPollRequest)
						.process0(generalPKIMessage);
				break;
			case PKIBody.TYPE_CERT_REP:
				new CertificationReplyValidationProcessor()
						.withEndEntityName(endEntityName)
						.withSubjectPrivateKey(privateKey)
						.withCertificateStore(certificateStore)
						.withPendingCertAnns(pendingCertAnns)
						.withPendingPollRequest(pendingPollRequest)
						.process1(generalPKIMessage);
				break;
			default:
				return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE,
						"Unexpected response type; "
								+ protectedPKIMessage.getBody().getType());
			}
		}
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public HttpResponse fetch(X500Name certSigner) {
		for (int i = 0; i < 10; i++) {
			int resCode = processFetch(certSigner);
			if(resCode!=HttpStatus.SC_OK) return ResponseFactory.create(resCode, null);
		}		
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public HttpResponse sendResponses(X500Name certSigner) throws ClientProtocolException, IOException{
		
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
//		PendingResponses pendingResponses = PendingResponses.getInstance(endEntityName);
		PKIMessage pkiMessage = pendingResponses.getNext();
		while(pkiMessage!=null){
			
			HttpClient httpclient = new DefaultHttpClient();
			HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
			HttpPost httpPost = new HttpPost(addressPrefix + REPSUFFIX);
			httpPost.setEntity(entity);
			httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
			HttpResponse sendingRsponse = httpclient.execute(httpPost);

			if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
				return sendingRsponse;

			
			pkiMessage = pendingResponses.getNext();
		}
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public HttpResponse announceCertificates() throws Exception{

		X509CertificateHolder certificateHolder = pendingCertAnns.getNext();

		while(certificateHolder!=null){
			CertificateAnnouncementHolder certificateAnnouncementHolder = new CertificateAnnouncementBuilder()
				.withSubjectName(endEntityName)
				.withSubjectCertificate(certificateHolder)
				.withPrivateKeyHolder(privateKeyHolder)
				.build();

			PKIMessage pkiMessage = certificateAnnouncementHolder.getPkiMessage();
			
			HttpClient httpclient = new DefaultHttpClient();
			HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
			HttpPost httpPost = new HttpPost(addressPrefix + REQSUFFIX);
			httpPost.setEntity(entity);
			httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
			HttpResponse sendingRsponse = httpclient.execute(httpPost);

			if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
				return sendingRsponse;
			
			certificateHolder = pendingCertAnns.getNext();
		}

		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}
	private void validate() {
		assert endEntityName != null : "Field clientName can not be null";
		assert addressPrefix != null : "Field addressPrefix can not be null";
	}
	
	private int processFetch(X500Name certSigner){
		if(certSigner==null) return HttpStatus.SC_BAD_REQUEST;
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
				
		X500Name serverX500Name = PlhCMPSystem.getServerName();
        PrivateKey subjectPrivateKey = privateKeyHolder.getPrivateKey(senderCertificate);
		ContentSigner subjectSigner;
		try {
			subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(ProviderUtils.bcProvider).build(subjectPrivateKey );
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCertificate);
		ProtectedPKIMessage mainMessage;
		try {
			InfoTypeAndValue itv = new InfoTypeAndValue(new FetchRequestTypesValue());
			GenMsgContent genMsgContent = new GenMsgContent(itv);
			mainMessage = new ProtectedPKIMessageBuilder(new GeneralName(endEntityName), new GeneralName(serverX500Name))
			    .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, genMsgContent))
			    .addCMPCertificate(senderCertificate)
			    .setMessageTime(new Date())
			    .setSenderKID(subjectKeyId)
			    .setSenderNonce(UUIDUtils.newUUIDAsBytes())
			    .setTransactionID(UUIDUtils.newUUIDAsBytes())
			    .build(subjectSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
        
        PKIMessage pkiMessage = mainMessage.toASN1Structure();

		HttpClient httpclient = new DefaultHttpClient();
		HttpEntity entity;
		try {
			entity = new ByteArrayEntity(pkiMessage.getEncoded());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		HttpPost httpPost = new HttpPost(addressPrefix + FETCHSUFFIX);
		httpPost.setEntity(entity);
		httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
		HttpResponse sendingRsponse;
		try {
			sendingRsponse = httpclient.execute(httpPost);
		} catch (ClientProtocolException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

		if (sendingRsponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
			return sendingRsponse.getStatusLine().getStatusCode();


		InputStream inputStream;
		try {
			inputStream = sendingRsponse.getEntity().getContent();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		GeneralPKIMessage generalPKIMessage;
		try {
			generalPKIMessage = new GeneralPKIMessage(
					IOUtils.toByteArray(inputStream));
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

		// Check message conformity
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity
				.check(generalPKIMessage);

		switch (protectedPKIMessage.getBody().getType()) {
			case PKIBody.TYPE_CERT_REQ:
				new CertificationRequestValidationProcessor()
					.setIssuerKeyId(subjectKeyId)
					.setIssuerName(endEntityName)
					.setIssuerPrivateKey(subjectPrivateKey)
					.setIssuerX509CertificateHolder(senderCertificate)
					.setPendingResponses(pendingResponses)
					.process0(generalPKIMessage);
				break;
			default:
				return HttpStatus.SC_NOT_ACCEPTABLE;
		}
		return HttpStatus.SC_OK;
	}
}
