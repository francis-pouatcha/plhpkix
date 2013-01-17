package org.adorys.plh.pkix.server.cmp.endentity;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Singleton;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.PrivateKeyUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
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
	private String serverName = PlhCMPSystem.getServerName();
	private X500Name serverX500Name = new X500Name(serverName);
	private byte[] serverKeyId;

	@PostConstruct
	private void initServer(){
		Provider provider = PlhCMPSystem.getProvider();

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
		
		List<EndEntityKey> serverKeys = endEntityKeyRepository.findEndEntityKeyBySubjectName(serverName);
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
		Provider provider = PlhCMPSystem.getProvider();
        KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance(PlhCMPSystem.getKeyPairAlgorithm(), provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
        
		kGen.initialize(PlhCMPSystem.getKeySizeForKeyPair());
        KeyPair keyPair = kGen.generateKeyPair();
        serverPrivateKey = keyPair.getPrivate();
        serverCertificate = V3CertificateUtils.makeSelfV3Certificate(keyPair, serverName, keyPair, serverName, provider);
		serverKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(serverCertificate);
        endEntityCertRepository.storeEndEntityCert(serverCertificate);
		
        EndEntityKey endEntityKey = new EndEntityKey();
        endEntityKey.setSubjectName(serverName);
		byte[] encryptedKeyData;
		try {
			encryptedKeyData = PrivateKeyUtils.encryptPrivateKey(keyPair.getPrivate(), provider, PlhCMPSystem.getServerPassword());
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
        endEntityKey.setEncryptedKeyData(encryptedKeyData);
		endEntityKeyRepository.storeEndEntityKey(endEntityKey );
	}
	
	public EndEntityHolder createEntityRecord(String endEntityName, X509CertificateHolder selfSignedCertificate){
		Provider provider = PlhCMPSystem.getProvider();
			    
		X509CertificateHolder serverSignedCertificate = V3CertificateUtils.makeV3Certificate(selfSignedCertificate, serverPrivateKey, serverName, provider);
		endEntityCertRepository.storeEndEntityCert(serverSignedCertificate);
        endEntityCertRepository.storeEndEntityCert(selfSignedCertificate);

		return  new EndEntityBuilder()
		.addCert(serverSignedCertificate)
		.addCert(selfSignedCertificate)
		.setSubjectName(endEntityName)
		.build();
	}

	public PrivateKey getServerPrivateKey() {
		return serverPrivateKey;
	}
	public X509CertificateHolder getServerCertificate() {
		return serverCertificate;
	}
	public String getServerName() {
		return serverName;
	}

	public byte[] getServerKeyId() {
		return serverKeyId;
	}

	public X500Name getServerX500Name() {
		return serverX500Name;
	}	
}
