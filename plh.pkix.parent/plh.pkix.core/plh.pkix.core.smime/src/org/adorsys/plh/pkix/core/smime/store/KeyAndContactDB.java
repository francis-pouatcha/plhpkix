package org.adorsys.plh.pkix.core.smime.store;

import java.security.KeyStore.Entry;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.KeyEntryAndCertificate;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class KeyAndContactDB {

	private List<KeyEntryAndCertificate> keyEntries = new ArrayList<KeyEntryAndCertificate>();
	private List<List<KeyEntryAndCertificate>> contactEntries = new ArrayList<List<KeyEntryAndCertificate>>();

	public KeyAndContactDB(KeyStoreWraper keyStoreWraper, ContactManager contactManager) {
		List<Entry> keyStoreEntries = keyStoreWraper.entries();
		keyEntries.addAll(KeyEntryAndCertificate.filterCertHolders(keyStoreEntries));
		List<List<Entry>> contacts = contactManager.listContacts();
		for (List<Entry> list : contacts) {
			contactEntries.add(KeyEntryAndCertificate.filterCertHolders(list));
		}
	}
	
	/**
	 * Return all entries with the given subject unique identifier.
	 * 
	 * @param subjectUID
	 * @return
	 */
	public List<KeyEntryAndCertificate> findContacts(DERBitString subjectUID) {
		if(subjectUID==null) return null;
		String subjectUidIn = subjectUID.getString();
		List<KeyEntryAndCertificate> r = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate kc : keyEntries) {
			String identifier = X500NameHelper.readSubjectUniqueIdentifier(kc.getCertHolder());
			if(subjectUidIn.equals(identifier)) r .add(kc);
		}
		for (List<KeyEntryAndCertificate> entryList : contactEntries) {
			for (KeyEntryAndCertificate kc : entryList) {
				String identifier = X500NameHelper.readSubjectUniqueIdentifier(kc.getCertHolder());
				if(subjectUidIn.equals(identifier)) r .add(kc);
			}
		}
		return r;
	}
	
	public List<KeyEntryAndCertificate> findContacts(SubjectPublicKeyInfo subjectPublicKeyInfo) {
		if(subjectPublicKeyInfo==null) return null;
		List<KeyEntryAndCertificate> r = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate kc : keyEntries) {
			if(subjectPublicKeyInfo.equals(kc.getCertHolder().getSubjectPublicKeyInfo()))
				r .add(kc);
		}
		for (List<KeyEntryAndCertificate> entryList : contactEntries) {
			for (KeyEntryAndCertificate kc : entryList) {
				if(subjectPublicKeyInfo.equals(kc.getCertHolder().getSubjectPublicKeyInfo()))
				r .add(kc);
			}
		}
		return r;
	}

	public List<KeyEntryAndCertificate> findContacts(SubjectKeyIdentifier subjectKeyIdentifier) {
		if(subjectKeyIdentifier==null) return null;
		List<KeyEntryAndCertificate> r = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate kc : keyEntries) {
			SubjectKeyIdentifier ski = KeyIdUtils.readSubjectKeyIdentifier(kc.getCertHolder());
			if(subjectKeyIdentifier.equals(ski))
				r .add(kc);
		}
		for (List<KeyEntryAndCertificate> entryList : contactEntries) {
			for (KeyEntryAndCertificate kc : entryList) {
				SubjectKeyIdentifier ski = KeyIdUtils.readSubjectKeyIdentifier(kc.getCertHolder());
				if(subjectKeyIdentifier.equals(ski))
					r .add(kc);
			}
		}
		return r;
	}
	
	public List<KeyEntryAndCertificate> findContacts(X500Name subjectDN) {
		if(subjectDN==null) return null;
		List<KeyEntryAndCertificate> r = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate kc : keyEntries) {
			if(subjectDN.equals(X500NameHelper.readSubjectDN(kc.getCertHolder())))
				r .add(kc);
		}
		for (List<KeyEntryAndCertificate> entryList : contactEntries) {
			for (KeyEntryAndCertificate kc : entryList) {
				if(subjectDN.equals(X500NameHelper.readSubjectDN(kc.getCertHolder())))
					r .add(kc);
			}
		}
		return r;
	}

	public List<KeyEntryAndCertificate> findContacts(List<String> subjectEmails) {
		if(subjectEmails==null || subjectEmails.isEmpty()) return null;
		List<KeyEntryAndCertificate> r = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate kc : keyEntries) {
			List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(kc.getCertHolder());
			for (String email : readSubjectEmails) {
				if(subjectEmails.contains(email)){
					r.add(kc);
					break;
				}
			}
		}
		for (List<KeyEntryAndCertificate> entryList : contactEntries) {
			for (KeyEntryAndCertificate kc : entryList) {
				List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(kc.getCertHolder());
				for (String email : readSubjectEmails) {
					if(subjectEmails.contains(email)){
						r.add(kc);
						break;
					}
				}
			}
		}
		return r;
	}
}
