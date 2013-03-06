package org.adorsys.plh.pkix.core.cmp;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.adorsys.plh.pkix.core.smime.contact.AccountManager;
import org.adorsys.plh.pkix.core.smime.store.FileContainerImpl;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.SimpleActionHandler;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileContainer;
import org.bouncycastle.asn1.x500.X500Name;

public class CMPandCMSClient {
	private static final String ACCOUNTSDIR = "accounts";
	
	private final FileWrapper accountsDir;
	private final ActionContext actionContext;

	private final Map<String, CMPAccount> cmpAccounts = new HashMap<String, CMPAccount>();
	
	public CMPandCMSClient(CMPMessenger cmpMessenger, File workspaceDir, String containerName, char[] containerKeyPass, char[] containerStorePass) {
		actionContext = new ActionContext();
		actionContext.put(CMPMessenger.class, cmpMessenger);
		actionContext.put(ActionHandler.class, new SimpleActionHandler());
		File containerDir = null;
		if(containerName==null){
			containerDir = new File(workspaceDir,""+BigInteger.probablePrime(7, new Random()));
		} else {
			containerDir = new File(workspaceDir, containerName);
		}
		FilesContainer clientContainer = createClientContainer(containerDir, containerKeyPass, containerStorePass);
		accountsDir = clientContainer.newFile(ACCOUNTSDIR);
		load();// load registered accounts
	}
	
	private void load() {
		String[] list = accountsDir.list();
		if(list==null) return;
		for (String accountDir : list) {
			load(accountsDir.newChild(accountDir));
		}
	}

	private void load(FileWrapper accountDir) {
		ActionContext accountContext = new ActionContext(actionContext);
		AccountManager accountManager = new AccountManager(accountContext, accountDir);
		accountContext.put(AccountManager.class, accountManager);
		CMPAccount cmpAccount = new CMPAccount(accountDir,accountContext);
		cmpAccounts.put(accountDir.getName(), cmpAccount);
	}
	
	public CMPAccount newAccount(String userName, String emails, char[] userSuppliedPassword) {
		ActionContext accountContext = new ActionContext(actionContext);
		FileWrapper accountDir = accountsDir.newChild("account_"+BigInteger.probablePrime(7, new Random()));
		AccountManager accountManager = new AccountManager(accountContext,accountDir, userName, emails, userSuppliedPassword);
		accountContext.put(AccountManager.class, accountManager);
		CMPAccount cmpAccount = new CMPAccount(accountDir, accountContext);
		cmpAccounts.put(accountDir.getName(), cmpAccount);
		return cmpAccount;
	}


	private FilesContainer createClientContainer(File rootDir, char[] containerKeyPass, char[] containerStorePass){//String dirName, String name, String  email, char[] containerKeyPass, char[] containerStorePass){
		FilesContainer keyStoreContainer = new UnprotectedFileContainer(rootDir);
		KeyStoreWraper containerKeyStoreWraper = new KeyStoreWraper(keyStoreContainer
				.newFile("containerKeyStore"), containerKeyPass, containerStorePass);

		PrivateKeyEntry containerMessagePrivateKeyEntry = containerKeyStoreWraper.findAnyMessagePrivateKeyEntry();
		if(containerMessagePrivateKeyEntry==null){
			new KeyPairBuilder()
				.withEndEntityName(new X500Name("cn="+rootDir))
				.withKeyStoreWraper(containerKeyStoreWraper)
				.build();
			containerMessagePrivateKeyEntry = containerKeyStoreWraper.findAnyMessagePrivateKeyEntry();
		}
		return new FileContainerImpl(containerMessagePrivateKeyEntry, rootDir);
	}
//	
//	public void requestCertification(X509CertificateHolder caCertificate) {
////		PrivateKeyEntry myCaPrivateKeyEntry = accountManager.getAccountKeyStoreWraper().findAnyCaPrivateKeyEntry();
////		X509CertificateHolder myCaCertificate = V3CertificateUtils.getX509CertificateHolder(myCaPrivateKeyEntry.getCertificate());
////		GeneralNames subjectAltName;
////		CertificationRequestBuilder builder = new CertificationRequestBuilder()
////			.withCa(true)
////			.withCertAuthorityName(caCertificate.getSubject())
////			.withPendingRequests(pendingRequests)
////			.withSubjectPreCertificate(myCaCertificate);
////		int[] keyUsageForCertificationAuthotity = KeyUsageUtils.getKeyUsageForCertificationAuthotity();
////		for (int keyUsage : keyUsageForCertificationAuthotity) {
////			builder = builder.withKeyUsage(keyUsage);
////		}
////		PendingRequestData pendingRequestData = builder.build(myCaPrivateKeyEntry.getPrivateKey());
////		
////		
////		AccountManager accountManager = caRepository.get(caPublicKeyIdentifier);
////		PrivateKeyEntry messagePrivateKeyEntry = accountManager.getAccountKeyStoreWraper().findAnyMessagePrivateKeyEntry();
////		
////		accountManager.certify(caPrivateKeyEntry.);
////		String certAuthorityCNLowerCase = certAuthorityCNAnyCase.toLowerCase();
////		
////		MockCMPandCMSClient adminClient = clients.getClient(certAuthorityCNLowerCase);
////		if(adminClient==null)
////			throw new IllegalArgumentException("Unknown Ca "+ certAuthorityCNLowerCase);
////		
////		X509CertificateHolder model = certificateStore.getCertificate(clientCN, clientCN);
////		model.getNotBefore();
////		adminClient.certify(model);
////		
////		X509CertificateHolder generatedCertificate = adminClient.getCertificate(client);
////		certificateStore.addCertificate(generatedCertificate);
//
//	}
//
//	public void fetchCertificate(String subjectCN,
//			String... certAuthorityCN) {
//		for (String issuerCN : certAuthorityCN) {
////			MockCMPandCMSClient mockClient = clients.getClient(issuerCN);			
////			if(mockClient==null) continue;
////			X509CertificateHolder x509CertificateHolder = mockClient.getCertificate(subjectCN);
////			certificateStore.addCertificate(x509CertificateHolder);
//		}
//	}
//	
//	public List<X509CertificateHolder> listCertificationRequests() {
//		return Collections.emptyList();
//	}
//
//	public void certify(X509CertificateHolder certificationRequest) {
////		X509CertificateHolder caCertificate = certificateStore.getCertificate(client);
////		PrivateKey caPrivateKey = privateKeyHolder.getPrivateKey(caCertificate);
////		
////		Provider provider = ProviderUtils.bcProvider;
////		X509CertificateHolder generatedCertificate = CertificationRequestValidationProcessor.generateCertificate(certificationRequest.getSubject(), 
////				certificationRequest.getNotBefore(), certificationRequest.getNotAfter(), 
////				PublicKeyUtils.getPublicKeySilent(certificationRequest, provider), 
////				caPrivateKey, caCertificate);
////		certificateStore.addCertificate(generatedCertificate);
//	}
//
//	public void reject(X509CertificateHolder certificationRequest) {
//		// TODO Auto-generated method stub
//
//	}
////
////	private X509CertificateHolder getCertificate(X500Name subjectDN){
////		return certificateStore.getCertificate(subjectDN, client);// client is issuer
////	}
//
////	private X509CertificateHolder getCertificate(String subjectCN){
////		return certificateStore.getCertificate(subjectCN, this.clientCN);// clientCN is issuer
////	}
//	
//	public void sendFile(String certIssuerCN, InputStream inputStream, OutputStream outputStream, String... reciepientNames) {
////		X509CertificateHolder x509CertificateHolder = certificateStore.getCertificate(clientCN, certIssuerCN);
////		try {
////			CMSSignEncryptUtils.signEncrypt(privateKeyHolder, 
////					x509CertificateHolder, 
////					inputStream, outputStream, certificateStore, reciepientNames);			
////		} catch (IOException e) {
////			throw new IllegalStateException(e);
////		}
//	}
//
//	public void receiveFile(InputStream inputStream, OutputStream outputStream) {
////		try {
////			CMSSignEncryptUtils.decryptVerify(privateKeyHolder, clientCN, 
////					certificateStore, inputStream, outputStream);
////		} catch (IOException e) {
////			throw new IllegalStateException(e);
////		}
//	}
//
//
//
}
