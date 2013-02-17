package org.adorsys.plh.pkix.server.cmp.endentity;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Date;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Singleton;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.PrivateKeyUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * This class will initialize the server if this has not yet happened.
 *    - Create self sign and store a key pair for the server
 *    - Create an EndEntity record for the administrator
 *    
 * @author francis
 *
 */
@Singleton
public class EndEntityInitializer {

	@EJB
	private EndEntityCertRepository endEntityCertRepository;
	
	@EJB
	private EndEntityKeyRepository endEntityKeyRepository;
	
	private PrivateKey serverPrivateKey;
	private X509CertificateHolder serverCertificate;
	private X500Name serverX500Name = PlhCMPSystem.getServerName();
	private String serverNameDBIdentifier = X500NameHelper.getCN(serverX500Name);
	private byte[] serverKeyId;

	@PostConstruct
	private void initServer(){
		Provider provider = ProviderUtils.bcProvider;

		// load the self signed certificate
		List<EndEntityCert> serverCerts = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(serverX500Name, serverX500Name);
		if(!serverCerts.isEmpty()){
			EndEntityCert serverCert = serverCerts.iterator().next();
			byte[] certificate = serverCert.getCertificate();
			try {
				serverCertificate = new X509CertificateHolder(certificate);
				serverKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(serverCertificate);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		} 
		
		List<EndEntityKey> serverKeys = endEntityKeyRepository.findEndEntityKeyBySubjectName(serverNameDBIdentifier);
		if(!serverKeys.isEmpty()){
			EndEntityKey serverKey = serverKeys.iterator().next();
			try {
				serverPrivateKey = PrivateKeyUtils.decryptPrivateKey(serverKey.getEncryptedKeyData(), 
						PlhCMPSystem.getServerPassword(), provider);
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
		}

		// create new Record.
		if(serverCertificate==null || serverPrivateKey==null)
			createServerRecord();
	}
	
	private void createServerRecord(){
		Provider provider = ProviderUtils.bcProvider;
        KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance(ProviderUtils.getKeyPairAlgorithm(), provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
        
		kGen.initialize(ProviderUtils.getKeySizeForKeyPair());
        KeyPair keyPair = kGen.generateKeyPair();
        serverPrivateKey = keyPair.getPrivate();
        serverCertificate = V3CertificateUtils.makeSelfV3Certificate(keyPair, serverX500Name, new Date(), DateUtils.addYears(new Date(), 1), provider);
		serverKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(serverCertificate);
        endEntityCertRepository.storeEndEntityCert(serverCertificate);
		
        EndEntityKey endEntityKey = new EndEntityKey();
        endEntityKey.setSubjectName(serverNameDBIdentifier);
		byte[] encryptedKeyData;
		try {
			encryptedKeyData = PrivateKeyUtils.encryptPrivateKey(keyPair.getPrivate(), provider, PlhCMPSystem.getServerPassword());
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
        endEntityKey.setEncryptedKeyData(encryptedKeyData);
		endEntityKeyRepository.storeEndEntityKey(endEntityKey );
	}
	
	public EndEntityHolder createEntityRecord(X509CertificateHolder endentitySSignedCertificate){
		Provider provider = ProviderUtils.bcProvider;
			    
		X509CertificateHolder serverSignedCertificate = V3CertificateUtils.makeV3Certificate(endentitySSignedCertificate, 
				serverPrivateKey, serverCertificate, endentitySSignedCertificate.getNotBefore(), 
				endentitySSignedCertificate.getNotAfter(), provider);
		endEntityCertRepository.storeEndEntityCert(serverSignedCertificate);
        endEntityCertRepository.storeEndEntityCert(endentitySSignedCertificate);

		return  new EndEntityBuilder()
		.addCert(serverSignedCertificate)
		.addCert(endentitySSignedCertificate)
		.setSubjectName(X500NameHelper.getCN(endentitySSignedCertificate.getSubject()))
		.build();
	}

	public PrivateKey getServerPrivateKey() {
		return serverPrivateKey;
	}
	public X509CertificateHolder getServerCertificate() {
		return serverCertificate;
	}

	public byte[] getServerKeyId() {
		return serverKeyId;
	}

	public X500Name getServerX500Name() {
		return serverX500Name;
	}	
}
