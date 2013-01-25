package org.adorsys.plh.pkix.client.cmp;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.certann.CertificateAnnouncementBuilder;
import org.adorys.plh.pkix.core.cmp.certann.CertificateAnnouncementHolder;
import org.adorys.plh.pkix.core.cmp.certrequest.CertificationReplyProcessor;
import org.adorys.plh.pkix.core.cmp.certrequest.CertificationRequestBuilder;
import org.adorys.plh.pkix.core.cmp.certrequest.CertificationRequestProcessor;
import org.adorys.plh.pkix.core.cmp.initrequest.InitializationRequestBuilder;
import org.adorys.plh.pkix.core.cmp.initrequest.InitializationRequestHolder;
import org.adorys.plh.pkix.core.cmp.initrequest.InitializationResponseProcessor;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageConformity;
import org.adorys.plh.pkix.core.cmp.pollrequest.PollReplyProcessor;
import org.adorys.plh.pkix.core.cmp.pollrequest.PollRequestBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PendingCertAnn;
import org.adorys.plh.pkix.core.cmp.stores.PendingPollRequest;
import org.adorys.plh.pkix.core.cmp.stores.PendingResponses;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.GeneralNameHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.adorys.plh.pkix.core.cmp.utils.X509CertificateHolderCollection;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
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

	public void initKeyPair() {
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder.getInstance(endEntityName);
		try {
			new KeyPairBuilder().withEndEntityName(endEntityName).withPrivateKeyHolder(privateKeyHolder).build();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public HttpResponse initialize(String certSignerString)
			throws OperatorCreationException, GeneralSecurityException,
			IOException, CertException, CMPException {

		validate();
		
		X500Name certSigner = new X500Name(certSignerString);
		
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
		X500Name serverX500Name = new X500Name(PlhCMPSystem.getServerName());
		
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
		new InitializationResponseProcessor().setCertificateStore(
				certificateStore).process(certTemplate, protectedPKIMessage);

		X509CertificateHolder certificate = certificateStore.getCertificate(
				certTemplate.getSubject(), certTemplate.getIssuer());
		if (certificate == null)
			return ResponseFactory.create(HttpStatus.SC_CONFLICT,
					"Missing server certificate");

		return ResponseFactory.create(HttpStatus.SC_OK, null);

	}

	public HttpResponse requestCertificate(String certAuthorityNameString)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, ClientProtocolException, IOException {

		validate();
		X500Name certAuthorityName = new X500Name(certAuthorityNameString);
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
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE,
					"Unexpected response type; "
							+ protectedPKIMessage.getBody().getType());
		}
	}

	public HttpResponse pollRequests(String certSignerString)
			throws NoSuchAlgorithmException, OperatorCreationException,
			CMPException, IOException {

		X500Name certSigner = new X500Name(certSignerString);
		
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
				return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE,
						"Unexpected response type; "
								+ protectedPKIMessage.getBody().getType());
			}
		}
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public HttpResponse fetch(String certSignerString) {
		for (int i = 0; i < 10; i++) {
			int resCode = processFetch(certSignerString);
			if(resCode!=HttpStatus.SC_OK) return ResponseFactory.create(resCode, null);
		}		
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public HttpResponse sendResponses(String certSignerString) throws ClientProtocolException, IOException{
		
		X500Name certSigner = new X500Name(certSignerString);
		
		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
		
		PendingResponses pendingResponses = PendingResponses.getInstance(endEntityName);
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

		PendingCertAnn pendingCertAnn = PendingCertAnn.getInstance(endEntityName);
		X509CertificateHolder certificateHolder = pendingCertAnn.getNext();

		while(certificateHolder!=null){
			CertificateAnnouncementHolder certificateAnnouncementHolder = new CertificateAnnouncementBuilder()
				.withSubjectName(endEntityName)
				.withSubjectCertificate(certificateHolder)
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
			
			certificateHolder = pendingCertAnn.getNext();
		}

		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}
	
	public CMPMessagingClient withClientName(String clientNameString) {
		this.endEntityName = new X500Name(clientNameString);
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
	
	private int processFetch(String cert){
		if(cert==null) return HttpStatus.SC_BAD_REQUEST;
		X500Name certSigner = new X500Name(cert);
		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(endEntityName, certSigner);
		if(senderCertificate==null)
			throw new IllegalStateException("No certificate with signer");
				
		X500Name serverX500Name = new X500Name(PlhCMPSystem.getServerName());
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder
				.getInstance(endEntityName);
        PrivateKey subjectPrivateKey = privateKeyHolder.getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(senderCertificate));
		ContentSigner subjectSigner;
		try {
			subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(PlhCMPSystem.getProvider()).build(subjectPrivateKey );
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCertificate);
		ProtectedPKIMessage mainMessage;
		try {
//			InfoTypeAndValue itv = new InfoTypeAndValue(new FetchRequestTypesValue());
//			GenMsgContent genMsgContent = new GenMsgContent(itv);
			mainMessage = new ProtectedPKIMessageBuilder(new GeneralName(endEntityName), new GeneralName(serverX500Name))
//			    .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, genMsgContent))
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
				new CertificationRequestProcessor()
					.setIssuerKeyId(subjectKeyId)
					.setIssuerName(endEntityName)
					.setIssuerPrivateKey(subjectPrivateKey)
					.setIssuerX509CertificateHolder(senderCertificate)
					.process(generalPKIMessage);
				break;
			default:
				return HttpStatus.SC_NOT_ACCEPTABLE;
		}
		return HttpStatus.SC_OK;
		
	}
}
