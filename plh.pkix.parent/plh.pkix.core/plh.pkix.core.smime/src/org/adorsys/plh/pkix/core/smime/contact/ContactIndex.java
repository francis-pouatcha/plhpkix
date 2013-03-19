package org.adorsys.plh.pkix.core.smime.contact;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;

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
	private Map<String, Set<String>> keyStoreId2Emails = new HashMap<String, Set<String>>();
	private Map<KeyStoreAlias, String> keyAlias2KeyStoreId = new HashMap<KeyStoreAlias, String>();
	private Map<String, String> publicKeyId2KeyStoreId = new HashMap<String, String>();
	private Map<String, String> subjectKeyId2KeyStoreId = new HashMap<String, String>();
	private Map<X500Name, String> caKeyStores = new HashMap<X500Name, String>();

	public void addContact(List<String> emails, KeyStoreAlias keyStoreAlias, String keyStoreId){
		for (String email : emails) {
			String keyStoreIdFoud = email2KeyStoreId.get(email);
			if(keyStoreIdFoud!=null && !StringUtils.equalsIgnoreCase(keyStoreId, keyStoreIdFoud))
				throw new IllegalArgumentException("Email in use by key store: "+keyStoreIdFoud + " so it can not be indexed for " + keyStoreId);
		}
		
		String keyStoreIdFound = keyAlias2KeyStoreId.get(keyStoreAlias);
		if(keyStoreIdFound!=null && !StringUtils.equalsIgnoreCase(keyStoreIdFound, keyStoreId)){
			throw new IllegalArgumentException("key alias already included in keystore : "+keyStoreIdFound + 
					" so it can not be indexed for " + keyStoreId);
		}
		
		String publicKeyIdHex = keyStoreAlias.getPublicKeyIdHex();
		keyStoreIdFound = publicKeyId2KeyStoreId.get(publicKeyIdHex);
		if(keyStoreIdFound!=null && !StringUtils.equalsIgnoreCase(keyStoreIdFound, keyStoreId)){
			throw new IllegalArgumentException("public key id already included in keystore : "+keyStoreIdFound + 
					" so it can not be indexed for " + keyStoreId);
		}

		String subjectKeyIdHex = keyStoreAlias.getSubjectKeyIdHex();
		keyStoreIdFound = subjectKeyId2KeyStoreId.get(subjectKeyIdHex);
		if(keyStoreIdFound!=null && !StringUtils.equalsIgnoreCase(keyStoreIdFound, keyStoreId)){
			throw new IllegalArgumentException("subject key id already included in keystore : "+keyStoreIdFound + 
					" so it can not be indexed for " + keyStoreId);
		}
		
		Set<String> emailSet = keyStoreId2Emails.get(keyStoreId);
		if(emailSet==null){
			emailSet = new HashSet<String>();
			keyStoreId2Emails.put(keyStoreId, emailSet);
		}
		for (String email : emails) {
			email2KeyStoreId.put(email, keyStoreId);
			emailSet.add(email);
		}
		keyAlias2KeyStoreId.put(keyStoreAlias, keyStoreId);
		publicKeyId2KeyStoreId.put(publicKeyIdHex, keyStoreId);
		subjectKeyId2KeyStoreId.put(subjectKeyIdHex, keyStoreId);
	}
	
	public String findKeyStoreIdByEmail(String email){
		return email2KeyStoreId.get(email);
	}

	public Set<String> listEmailContacts() {
		return email2KeyStoreId.keySet();
	}
	
	public Set<KeyStoreAlias> keyStoreAliases(){
		return keyAlias2KeyStoreId.keySet();
	}
	
	public String findByKeyStoreAlias(KeyStoreAlias keyStoreAlias){
		return keyAlias2KeyStoreId.get(keyStoreAlias);
	}
	
	public String findByPublicKeyId(String publicKeyIdHex){
		return publicKeyId2KeyStoreId.get(publicKeyIdHex);
	}
	
	public String findBySubjectKeyId(String subjectKeyIdHex){
		return subjectKeyId2KeyStoreId.get(subjectKeyIdHex);
	}

	public String getCaKeyStoreId(X500Name subject) {
		return caKeyStores .get(subject);
		
	}

	public void putCaKeyStoreId(X500Name subject, String keyStoreId) {
		caKeyStores.put(subject, keyStoreId);
	}
}
