package org.adorsys.plh.pkix.core.smime.contact;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;

public class ContactManagerHolder {

	private static final String KEYSTORE_FILE_NAME="accountKeyStore";
	private final ContactManager contactManager;
	private final KeyStoreWraper keyStoreWraper;
	private final FilesContainer fileContainer;
	
	/**
	 * Create a contact manager.
	 * 
	 * @param container
	 * @param rootDir
	 * @param x500DN
	 * @param email
	 * @param storePass shall be kept secret.
	 * @param keyPass shall be kept secret.
	 */
	public ContactManagerHolder(FilesContainer container, File rootDir, String x500DN, String email, char[] storePass, char[] keyPass){
		this.fileContainer = container;
		
		X500Name subjectX500Name = X500NameHelper.makeX500Name(x500DN, email);
		GeneralNames subjectAlternativeNames = X500NameHelper.makeSubjectAlternativeName(subjectX500Name, Arrays.asList(email));
		
		FileWrapper keyStoreFile = container.newFile(KEYSTORE_FILE_NAME);
		keyStoreWraper = new KeyStoreWraper(keyStoreFile, keyPass, storePass);
		PrivateKeyEntry messagePrivateKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
		if(messagePrivateKeyEntry==null){
			new KeyPairBuilder()
					.withEndEntityName(subjectX500Name)
					.withKeyStoreWraper(keyStoreWraper)
					.withSubjectAlternativeNames(subjectAlternativeNames)
					.build();
			messagePrivateKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
		}
		// the public key id of the container is used as the store and key pass for all contact records.
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(messagePrivateKeyEntry.getCertificate().getPublicKey());
		contactManager = new ContactManager(fileContainer, publicKeyIdentifier.toCharArray(), publicKeyIdentifier.toCharArray());
		
	}

	public ContactManager getContactManager() {
		return contactManager;
	}

	public KeyStoreWraper getKeyStoreWraper() {
		return keyStoreWraper;
	}
}
