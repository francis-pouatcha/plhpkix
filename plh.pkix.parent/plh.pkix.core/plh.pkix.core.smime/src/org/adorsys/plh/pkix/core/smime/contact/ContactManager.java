package org.adorsys.plh.pkix.core.smime.contact;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Manages contacts of an end entity. Each contact is stored in a proper key store.
 * 
 * @author francis
 *
 */
public class ContactManager {

	public static final String CONTACT_DIR_NAME = "contacts";
	
	private final FilesContainer container;
	private final char[] storePass;
	private final char[] keyPass;

	// The cache. TODO replace with clean cache.
	// The key is the keyStoreId, or the relative file name of the 
	// keyStore in the scope of the FileContainer.
	private final Map<String, KeyStoreWraper> contacts = new HashMap<String, KeyStoreWraper>();
	
	private final ContactIndex contactIndex;
	private final FileWrapper contactDir;

	public ContactManager(FilesContainer container, char[] storePass, char[] keyPass) {
		this.container = container;
		this.storePass = storePass;
		this.keyPass = keyPass;
		contactDir = container.newFile(CONTACT_DIR_NAME);
		contactIndex = new ContactIndex(this);
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	public FileWrapper getContactDir() {
		return contactDir;
	}

	public char[] getStorePass() {
		return storePass;
	}

	public char[] getKeyPass() {
		return keyPass;
	}

	/**
	 * Add a new contact.
	 * 
	 * @param certificate: the certificate of the contact.
	 * @throws PlhCheckedException 
	 * 
	 */
	public void addContact(X509CertificateHolder certHolder) throws PlhCheckedException{
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
		List<String> keyStores = new ArrayList<String>();
		for (String email : subjectEmails) {
			String keyStoreId = contactIndex.getKeyStoreId(email);
			if(keyStoreId!=null && !keyStores.contains(keyStoreId))
				keyStores.add(keyStoreId);
		}
		if(keyStores.size()>2) throw new IllegalArgumentException("Certificate contains key spread into more than two keystore.");
		
		String keyStoreId = null;
		KeyStoreWraper keyStoreWraper = null;
		if(keyStores.isEmpty()){
			keyStoreId = UUID.randomUUID().toString();			
		} else {
			keyStoreId = keyStores.iterator().next();
			keyStoreWraper = contacts.get(keyStoreId);
		}
		if(keyStoreWraper==null){
			FileWrapper keyStoreFile = container.newFile(CONTACT_DIR_NAME, keyStoreId);
			keyStoreWraper = new KeyStoreWraper(keyStoreFile, keyPass, storePass);
			contacts.put(keyStoreId, keyStoreWraper);
		}
		org.bouncycastle.asn1.x509.Certificate certificate = V3CertificateUtils.getX509BCCertificate(certHolder);
		keyStoreWraper.importCertificates(certificate);
		for (String email : subjectEmails) {
			contactIndex.addContact(email, keyStoreId);
		}
	}
	
	public KeyStoreWraper getContact(String email){
		String keyStoreId = contactIndex.getKeyStoreId(email);
		if(keyStoreId==null) return null;
		return loadKeyStore(keyStoreId);
	}
	
	private KeyStoreWraper loadKeyStore(String keyStoreId){
		KeyStoreWraper keyStoreWraper = contacts.get(keyStoreId);
		if(keyStoreWraper!=null) return keyStoreWraper;
		FileWrapper keyStoreFile = container.newFile(keyStoreId);
		keyStoreWraper = new KeyStoreWraper(keyStoreFile, keyStoreId.toCharArray(), keyStoreId.toCharArray());
		contacts.put(keyStoreId, keyStoreWraper);
		return keyStoreWraper;
	}
}
