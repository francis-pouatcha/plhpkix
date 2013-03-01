package org.adorsys.plh.pkix.core.test.cmp;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.CMPClient;
import org.adorsys.plh.pkix.core.cmp.CMSClient;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class MockCMPandCMSClient implements CMPClient, CMSClient {

	// Client cache. Short cutting messaging functionality for test purpose
	private ClientMap clients;
	private KeyStoreWraper keyStoreWraper;
	private X500Name client;
	private String clientCN;
	
	public MockCMPandCMSClient(ClientMap clients) {
		super();
		this.clients = clients;
	}

	@Override
	public void register(String name, String email) {
		client = X500NameHelper.makeX500Name(name, email);
//		clientCN = X500NameHelper.getCN(client);
		
//		
//		privateKeyHolder = new InMemoryPrivateKeyHolder();
//		certificateStore = new InMemoryCertificateStore();
//		
//		new KeyPairBuilder()
//		.withEndEntityName(client)
//		.withPrivateKeyHolder(privateKeyHolder)
//		.withCertificateStore(certificateStore)
//		.build0();
//		
//		// Store for server
//		clients.putClient(clientCN, this);
	}

	@Override
	public void requestCertification(String certAuthorityCNAnyCase) {
		
//		String certAuthorityCNLowerCase = certAuthorityCNAnyCase.toLowerCase();
//		
//		MockCMPandCMSClient adminClient = clients.getClient(certAuthorityCNLowerCase);
//		if(adminClient==null)
//			throw new IllegalArgumentException("Unknown Ca "+ certAuthorityCNLowerCase);
//		
//		X509CertificateHolder model = certificateStore.getCertificate(clientCN, clientCN);
//		model.getNotBefore();
//		adminClient.certify(model);
//		
//		X509CertificateHolder generatedCertificate = adminClient.getCertificate(client);
//		certificateStore.addCertificate(generatedCertificate);

	}

	@Override
	public void fetchCertificate(String subjectCN,
			String... certAuthorityCN) {
		for (String issuerCN : certAuthorityCN) {
//			MockCMPandCMSClient mockClient = clients.getClient(issuerCN);			
//			if(mockClient==null) continue;
//			X509CertificateHolder x509CertificateHolder = mockClient.getCertificate(subjectCN);
//			certificateStore.addCertificate(x509CertificateHolder);
		}
	}
	
	@Override
	public List<X509CertificateHolder> listCertificationRequests() {
		return Collections.emptyList();
	}

	@Override
	public void certify(X509CertificateHolder certificationRequest) {
//		X509CertificateHolder caCertificate = certificateStore.getCertificate(client);
//		PrivateKey caPrivateKey = privateKeyHolder.getPrivateKey(caCertificate);
//		
//		Provider provider = ProviderUtils.bcProvider;
//		X509CertificateHolder generatedCertificate = CertificationRequestValidationProcessor.generateCertificate(certificationRequest.getSubject(), 
//				certificationRequest.getNotBefore(), certificationRequest.getNotAfter(), 
//				PublicKeyUtils.getPublicKeySilent(certificationRequest, provider), 
//				caPrivateKey, caCertificate);
//		certificateStore.addCertificate(generatedCertificate);
	}

	@Override
	public void reject(X509CertificateHolder certificationRequest) {
		// TODO Auto-generated method stub

	}
//
//	private X509CertificateHolder getCertificate(X500Name subjectDN){
//		return certificateStore.getCertificate(subjectDN, client);// client is issuer
//	}

//	private X509CertificateHolder getCertificate(String subjectCN){
//		return certificateStore.getCertificate(subjectCN, this.clientCN);// clientCN is issuer
//	}
	
	@Override
	public void sendFile(String certIssuerCN, InputStream inputStream, OutputStream outputStream, String... reciepientNames) {
//		X509CertificateHolder x509CertificateHolder = certificateStore.getCertificate(clientCN, certIssuerCN);
//		try {
//			CMSSignEncryptUtils.signEncrypt(privateKeyHolder, 
//					x509CertificateHolder, 
//					inputStream, outputStream, certificateStore, reciepientNames);			
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
	}

	@Override
	public void receiveFile(InputStream inputStream, OutputStream outputStream) {
//		try {
//			CMSSignEncryptUtils.decryptVerify(privateKeyHolder, clientCN, 
//					certificateStore, inputStream, outputStream);
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
	}
}
