package org.adorsys.plh.pkix.core.smime.contact;

import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
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

	// The cache. TODO replace with clean cache.
	// The key is the keyStoreId, or the relative file name of the 
	// keyStore in the scope of the FileContainer.
	private final Map<String, KeyStoreWraper> contacts = new HashMap<String, KeyStoreWraper>();
	
	private final ContactIndex contactIndex;
	private final FileWrapper contactsDir;

	public ContactManager(FileWrapper contactsDir) {
		this.contactsDir = contactsDir;
		contactIndex = new ContactIndex(this);
		rescan();
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
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
			FileWrapper contactDir = contactsDir.newChild(keyStoreId);
			keyStoreWraper = contactDir.getKeyStoreWraper();
			contacts.put(keyStoreId, keyStoreWraper);
		}
		keyStoreWraper.importCertificates(V3CertificateUtils.getX509BCCertificate(certHolder));
		for (String email : subjectEmails) {
			contactIndex.addContact(email, keyStoreId);
		}
	}
	
	public List<KeyStore.Entry> getContact(String email){
		String keyStoreId = contactIndex.getKeyStoreId(email);
		if(keyStoreId==null) return null;
		return loadKeyStore(keyStoreId).entries();
	}
	
	private KeyStoreWraper loadKeyStore(String keyStoreId){
		KeyStoreWraper keyStoreWraper = contacts.get(keyStoreId);
		if(keyStoreWraper!=null) return keyStoreWraper;
		FileWrapper contactDir = contactsDir.newChild(keyStoreId);
		keyStoreWraper = contactDir.getKeyStoreWraper();
		contacts.put(keyStoreId, keyStoreWraper);
		return keyStoreWraper;
	}

	private void rescan(){
		contacts.clear();
		String[] list = contactsDir.list();
		if(list==null) return;
		for (String keyStoreId : list) {
			FileWrapper contactDir = contactsDir.newChild(keyStoreId);
			if(!contactDir.exists()) continue;
			KeyStoreWraper keyStoreWraper = contactDir.getKeyStoreWraper();
			List<X509CertificateHolder> certificates = keyStoreWraper.loadCertificates();
			for (X509CertificateHolder certHolder : certificates) {
				List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
				for (String email : subjectEmails) {
					contactIndex.addContact(email, keyStoreId);
				}
			}
		}
	}

	public List<List<KeyStore.Entry>> listContacts() {
		Set<String> keyStoreIds = contactIndex.listContacts();
		List<List<Entry>> result = new ArrayList<List<Entry>>();
		for (String keyStoreId : keyStoreIds) {
			KeyStoreWraper keyStoreWraper = loadKeyStore(keyStoreId);
			result.add(keyStoreWraper.entries());
		}
		return result;
	}
}
