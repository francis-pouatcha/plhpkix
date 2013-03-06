package org.adorsys.plh.pkix.core.smime.contact;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Simple index file of all contacts maintained by an end entity.
 * Each contact is represented by one or many records.
 * Each record has the form <StrictEmailAddress>=<KeyStoreLocation>.
 * Many Emails can point to the same key store. Meaning that they represent
 * the same end entity. Each email is associated with atleast one certificate.
 * A single certificate might also represent many emails.
 * 
 * Emails must be store in the subjectAlternativeName extension of the certificate.
 * 
 * If the user has many emails and among them a prefered email address, it can be stored
 * in the <emailAddress> component of the common name. Otherwise the application
 * will consider prefered the first email address in the list of emails listed in the 
 * subjectAlternativeName extension.
 * 
 * The index key is the lower case strict version of the email. This means that 
 * <Francis Pouatcha Signing>"fpo@me.com" is equivalent to 
 * <Francis Pouatcha Ca>"fpo@me.com" because both map to fpo@me.com.
 * 
 * Is an email address is reserved by an endentity, the application will
 * not allow the storage of that email for another end entity. Tha application
 * will refuse to import the corresponding contact.
 * 
 * If a certificate is signed by a address authority, this certificate will have 
 * precedence over existing self signed certificates.
 * 
 * @author francis
 *
 */
public class ContactIndex {
	
	private Map<String, String> email2KeyStoreId = new HashMap<String, String>();
	private Map<String, List<String>> keyStoreId2Emails = new HashMap<String, List<String>>();
	
	public ContactIndex(ContactManager contactManager) {
	}

	public void addContact(String email, String keyStoreId){
		if(email2KeyStoreId.containsKey(email)) return;
		email2KeyStoreId.put(email, keyStoreId);
		if(keyStoreId2Emails.containsKey(keyStoreId)){
			List<String> list = keyStoreId2Emails.get(keyStoreId);
			if(!list.contains(email))list.add(email);
		} else {
			ArrayList<String> list = new ArrayList<String>();
			list.add(email);
			keyStoreId2Emails.put(keyStoreId, list);
		}
	}
	
	public String getKeyStoreId(String email){
		return email2KeyStoreId.get(email);
	}

	public Set<String> listContacts() {
		return email2KeyStoreId.keySet();
	}
}
