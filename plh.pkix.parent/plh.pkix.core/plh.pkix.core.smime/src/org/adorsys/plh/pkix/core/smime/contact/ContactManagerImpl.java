package org.adorsys.plh.pkix.core.smime.contact;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraperUtils;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Manages contacts of an end entity. Each contact is stored in a proper key store.
 * 
 * @author francis
 *
 */
public class ContactManagerImpl implements ContactManager {

	// The cache. TODO replace with clean cache.
	// The key is the keyStoreId, or the relative file name of the 
	// keyStore in the scope of the FileContainer.
	private final Map<String, KeyStoreWraper> contacts = new HashMap<String, KeyStoreWraper>();
	
	private ContactIndex contactIndex;
	private final FileWrapper contactsDir;
	// only key store carrying a private key
	private KeyStoreWraper mainKeyStoreWraper;
	
	public ContactManagerImpl(KeyStoreWraper mainKeyStoreWraper, FileWrapper contactsDir) {
		this.contactsDir = new NullSafeFileWrapper(contactsDir);
		this.mainKeyStoreWraper = mainKeyStoreWraper;
		contacts.put(mainKeyStoreWraper.getId(), mainKeyStoreWraper);
		rescan();
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#addCertEntry(org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public void addCertEntry(X509CertificateHolder certHolder) throws PlhCheckedException{
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
		Set<String> keyStores = new HashSet<String>();
		for (String email : subjectEmails) {
			String keyStoreId = contactIndex.findKeyStoreIdByEmail(email);
			if(keyStoreId!=null)keyStores.add(keyStoreId);
		}
		if(keyStores.size()>2) throw new IllegalArgumentException("Certificate contains key spread into more than two keystore.");
		String keyStoreId = null;
		if(!keyStores.isEmpty())
			keyStoreId = keyStores.iterator().next();
		
		String caKeyStoreId = null;
		if(V3CertificateUtils.isCaKey(certHolder)){
			X500Name subject = certHolder.getSubject();
			caKeyStoreId = contactIndex.getCaKeyStoreId(subject);
			if(caKeyStoreId!=null && keyStoreId!=null && !StringUtils.equals(keyStoreId, caKeyStoreId))
				if(keyStores.size()>2) throw new IllegalArgumentException("Ca subject is included in aother key store.");

			if(keyStoreId==null)
				keyStoreId = caKeyStoreId;
		}
		
		if(keyStoreId==null)
			keyStoreId = UUID.randomUUID().toString();			
		

		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, TrustedCertificateEntry.class);
		contactIndex.addContact(subjectEmails, keyStoreAlias, keyStoreId);
		if(caKeyStoreId!=null)
			contactIndex.putCaKeyStoreId(certHolder.getSubject(),keyStoreId);

		KeyStoreWraper keyStoreWraper = loadKeyStore(keyStoreId);
		if(keyStoreWraper!=null)
			keyStoreWraper.importCertificates(V3CertificateUtils.getX509BCCertificate(certHolder));
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#addPrivateKeyEntry(java.security.Key, java.security.cert.Certificate[])
	 */
	@Override
	public void addPrivateKeyEntry(Key key,Certificate[] chain) throws PlhCheckedException{
		X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(chain[0]);
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
		Set<String> keyStores = new HashSet<String>();
		for (String email : subjectEmails) {
			String keyStoreId = contactIndex.findKeyStoreIdByEmail(email);
			if(keyStoreId!=null)keyStores.add(keyStoreId);
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
			if(keyStoreWraper!=null)
				contacts.put(keyStoreId, keyStoreWraper);
		}
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, TrustedCertificateEntry.class);
		contactIndex.addContact(subjectEmails, keyStoreAlias, keyStoreId);
		if(keyStoreWraper!=null){
			keyStoreWraper.importCertificates(V3CertificateUtils.getX509BCCertificate(certHolder));
			keyStoreWraper.setPrivateKeyEntry(key, chain);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[])
	 */
	@Override
	public void importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
		X509CertificateHolder certHldr = new X509CertificateHolder(certArray[0]);
		String publicKeyIdHex = KeyIdUtils.createPublicKeyIdentifierAsString(certHldr);
		String keyStoreId = contactIndex.findByPublicKeyId(publicKeyIdHex);
		if(keyStoreId==null){
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_missingPrivateKeyEntry,
                    new Object[] { certHldr.getSubject(), certHldr.getIssuer(), certHldr.getSerialNumber()});
            throw new PlhCheckedException(msg);
		}
		
		KeyStoreWraper loadedKeyStore = loadKeyStore(keyStoreId);
		if(loadedKeyStore!=null)
			loadedKeyStore.importIssuedCertificate(certArray);
	}


	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryBySerialNumber(java.lang.Class, java.math.BigInteger)
	 */
	@Override
	public <T extends Entry> T findEntryBySerialNumber(Class<T> klass,
			BigInteger serialNumber) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectBySerialNumber(keyStoreAliases(), serialNumber, klass);
		return findEntryByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByPublicKeyInfo(java.lang.Class, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo)
	 */
	@Override
	public <T extends Entry> T findEntryByPublicKeyInfo(Class<T> klass,
			SubjectPublicKeyInfo subjectPublicKeyInfo) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(keyStoreAliases(), subjectPublicKeyInfo, klass);
		return findEntryByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByPublicKeyInfo(java.lang.Class, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo)
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByPublicKeyInfo(Class<T> klass,
			SubjectPublicKeyInfo subjectPublicKeyInfo) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(keyStoreAliases(), subjectPublicKeyInfo, klass);
		return findEntriesByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByPublicKeyIdentifier(java.lang.Class, byte[])
	 */
	@Override
	public <T extends Entry> T findEntryByPublicKeyIdentifier(Class<T> klass,
			byte[] publicKeyIdentifier) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(keyStoreAliases(), publicKeyIdentifier, klass);
		return findEntryByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByPublicKeyIdentifier(java.lang.Class, byte[])
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByPublicKeyIdentifier(
			Class<T> klass, byte[] publicKeyIdentifier) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(keyStoreAliases(), publicKeyIdentifier, klass);
		return findEntriesByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryBySubjectKeyIdentifier(java.lang.Class, byte[])
	 */
	@Override
	public <T extends Entry> T findEntryBySubjectKeyIdentifier(Class<T> klass,
			byte[] subjectKeyIdentifierBytes) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(keyStoreAliases(), subjectKeyIdentifierBytes, klass);
		return findEntryByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesBySubjectKeyIdentifier(java.lang.Class, byte[])
	 */
	@Override
	public <T extends Entry> List<T> findEntriesBySubjectKeyIdentifier(
			Class<T> klass, byte[] subjectKeyIdentifierBytes) {
		 List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(keyStoreAliases(), subjectKeyIdentifierBytes, klass);
		return findEntriesByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findMessageEntryByIssuerCertificate(java.lang.Class, org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public <T extends Entry> T findMessageEntryByIssuerCertificate(
			Class<T> klass, X509CertificateHolder... issuerCertificates) {
		List<KeyStoreAlias> keyStoreAliases = new ArrayList<KeyStoreAlias>();
		for (X509CertificateHolder x509CertificateHolder : issuerCertificates) {
			keyStoreAliases.add(new KeyStoreAlias(x509CertificateHolder, klass));
		}
		return findEntryByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findMessageEntriesByIssuerCertificate(java.lang.Class, org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public <T extends Entry> List<T> findMessageEntriesByIssuerCertificate(
			Class<T> klass, X509CertificateHolder... issuerCertificates) {
		List<KeyStoreAlias> keyStoreAliases = new ArrayList<KeyStoreAlias>();
		for (X509CertificateHolder x509CertificateHolder : issuerCertificates) {
			keyStoreAliases.add(new KeyStoreAlias(x509CertificateHolder, klass));
		}
		return findEntriesByAlias(klass, keyStoreAliases);
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findMessageEntryByEmail(java.lang.Class, java.lang.String)
	 */
	@Override
	public <T extends Entry> T findMessageEntryByEmail(Class<T> klass,
			String... emails) {
		if(emails==null || emails.length==0) return null;
		Set<String> visitedIds = new HashSet<String>();
		for (String email : emails) {
			String keyStoreId = contactIndex.findKeyStoreIdByEmail(email);
			if(keyStoreId==null) continue;
			if(visitedIds.contains(keyStoreId)) continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			T entry = loadedKeyStore.findMessageEntryByEmail(klass, emails);
			if(entry!=null) return entry;
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findMessageEntriesByEmail(java.lang.Class, java.lang.String)
	 */
	@Override
	public <T extends Entry> List<T> findMessageEntriesByEmail(Class<T> klass,
			String... emails) {
		if(emails==null || emails.length==0) return null;
		Set<String> visitedIds = new HashSet<String>();
		for (String email : emails) {
			String keyStoreId = contactIndex.findKeyStoreIdByEmail(email);
			if(keyStoreId==null) continue;
			if(visitedIds.contains(keyStoreId)) continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			List<T> entries = loadedKeyStore.findMessageEntriesByEmail(klass, emails);
			if(entries!=null && !entries.isEmpty()) return entries;
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCaEntryBySubject(java.lang.Class, org.bouncycastle.asn1.x500.X500Name)
	 */
	@Override
	public <T extends Entry> T findCaEntryBySubject(Class<T> klass,
			X500Name... subjects) {
		Set<String> visitedIds = new HashSet<String>();
		for (X500Name subject : subjects) {
			String caKeyStoreId = contactIndex.getCaKeyStoreId(subject);
			if(caKeyStoreId==null) continue;
			if(visitedIds.contains(caKeyStoreId)) continue;
			visitedIds.add(caKeyStoreId);
			KeyStoreWraper keyStore = loadKeyStore(caKeyStoreId);
			if(keyStore==null) continue;
			T caEntry = keyStore.findCaEntry(klass, subjects);
			if(caEntry!=null) return caEntry;
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCaEntriesBySubject(java.lang.Class, org.bouncycastle.asn1.x500.X500Name)
	 */
	@Override
	public <T extends Entry> List<T> findCaEntriesBySubject(Class<T> klass,
			X500Name... subjects) {
		Set<String> visitedIds = new HashSet<String>();
		List<T> result = new ArrayList<T>();
		for (X500Name subject : subjects) {
			String caKeyStoreId = contactIndex.getCaKeyStoreId(subject);
			if(caKeyStoreId==null) continue;
			if(visitedIds.contains(caKeyStoreId)) continue;
			visitedIds.add(caKeyStoreId);
			KeyStoreWraper keyStore = loadKeyStore(caKeyStoreId);
			if(keyStore==null) continue;
			List<T> caEntries = keyStore.findCaEntries(klass, subjects);
			if(caEntries!=null) result.addAll(caEntries);
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByAlias(java.lang.Class, java.util.List)
	 */
	@Override
	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases) {
		if(keyStoreAliases==null || keyStoreAliases.isEmpty()) return null;
		Set<String> visitedIds = new HashSet<String>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			String keyStoreId = contactIndex.findByKeyStoreAlias(keyStoreAlias);
			if(keyStoreId==null)continue;
			if(visitedIds.contains(keyStoreId))continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			T entry = loadedKeyStore.findEntryByAlias(klass, keyStoreAliases);
			if(entry!=null) return entry;
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByAlias(java.lang.Class, org.adorsys.plh.pkix.core.utils.KeyStoreAlias)
	 */
	@Override
	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntryByAlias(klass, Arrays.asList(keyStoreAliases));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByAlias(java.lang.Class, java.util.List)
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases) {
		if(keyStoreAliases==null || keyStoreAliases.isEmpty()) return null;
		Set<String> visitedIds = new HashSet<String>();
		List<T> result = new ArrayList<T>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			String keyStoreId = contactIndex.findByKeyStoreAlias(keyStoreAlias);
			if(keyStoreId==null)continue;
			if(visitedIds.contains(keyStoreId))continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			List<T> entries = loadedKeyStore.findEntriesByAlias(klass, keyStoreAliases);
			if(entries!=null) result .addAll(entries);
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByAlias(java.lang.Class, org.adorsys.plh.pkix.core.utils.KeyStoreAlias)
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntriesByAlias(klass, Arrays.asList(keyStoreAliases));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#keyStoreAliases()
	 */
	@Override
	public List<KeyStoreAlias> keyStoreAliases() {
		return new ArrayList<KeyStoreAlias>(contactIndex.keyStoreAliases());
	}

	private KeyStoreWraper loadKeyStore(String keyStoreId){
		KeyStoreWraper keyStoreWraper = contacts.get(keyStoreId);
		if(keyStoreWraper!=null) return keyStoreWraper;		
		FileWrapper contactDir = contactsDir.newChild(keyStoreId);
		keyStoreWraper = contactDir.getKeyStoreWraper();
		if(keyStoreWraper!=null)
			contacts.put(keyStoreId, keyStoreWraper);
		return keyStoreWraper;
	}

	private void rescan(){
		contactIndex = new ContactIndex();

		contacts.clear();
		
		// Process main
		processScan(mainKeyStoreWraper);
		
		// process contacts
		String[] list = contactsDir.list();
		if(list==null || list.length==0) return;
		for (String keyStoreId : list) {
			FileWrapper contactDir = contactsDir.newChild(keyStoreId);
			if(!contactDir.exists()) continue;
			KeyStoreWraper keyStoreWraper = contactDir.getKeyStoreWraper();
			processScan(keyStoreWraper);
		}
	}
	
	private void processScan(KeyStoreWraper keyStoreWraper){
		String keyStoreId = keyStoreWraper.getId();
		contacts.put(keyStoreId, keyStoreWraper);
		
		List<KeyStoreAlias> keyStoreAliases = keyStoreWraper.keyStoreAliases();
		Certificate certificate = null;
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class)){
				PrivateKeyEntry pkEntry = keyStoreWraper.findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
				certificate = pkEntry.getCertificate();
				List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(certificate);
				contactIndex.addContact(readSubjectEmails, keyStoreAlias, keyStoreId);
			} else if(keyStoreAlias.isEntryType(TrustedCertificateEntry.class)){
				TrustedCertificateEntry trustedCertificateEntry = keyStoreWraper.findEntryByAlias(TrustedCertificateEntry.class, keyStoreAlias);
				certificate = trustedCertificateEntry.getTrustedCertificate();
				List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(certificate);
				contactIndex.addContact(readSubjectEmails, keyStoreAlias, keyStoreId);
			} else if(keyStoreAlias.isEntryType(SecretKeyEntry.class)){
				List<String> emails = Collections.emptyList();
				contactIndex.addContact(emails, keyStoreAlias, keyStoreId);
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#getTrustAnchors()
	 */
	@Override
	public Set<TrustAnchor> getTrustAnchors(){
		Set<KeyStoreAlias> keyStoreAliases = contactIndex.keyStoreAliases();
		Set<KeyStoreAlias> selfSignedPrivate = new HashSet<KeyStoreAlias>();
		Set<KeyStoreAlias> selfSignedTrusted = new HashSet<KeyStoreAlias>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(!keyStoreAlias.isSelfSigned()) continue;
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class)){
				selfSignedPrivate.add(keyStoreAlias);
			} else if (keyStoreAlias.isEntryType(TrustedCertificateEntry.class)){
				selfSignedTrusted.add(keyStoreAlias);
			}
		}
		
		Map<KeyStoreAlias, PrivateKeyEntry> privateKeyEntries = new HashMap<KeyStoreAlias, KeyStore.PrivateKeyEntry>();
		for (KeyStoreAlias keyStoreAlias : selfSignedPrivate) {
			String keyStoreId = contactIndex.findByKeyStoreAlias(keyStoreAlias);
			KeyStoreWraper keyStore = loadKeyStore(keyStoreId);
			if(keyStore==null) continue;
			PrivateKeyEntry privateKeyEntry = keyStore.findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
			if(V3CertificateUtils.isCaKey(privateKeyEntry.getCertificate())){
				privateKeyEntries.put(keyStoreAlias, privateKeyEntry);
			}
		}
		List<TrustedCertificateEntry> trustedCertificateEntries = new ArrayList<TrustedCertificateEntry>();
		Set<java.util.Map.Entry<KeyStoreAlias,PrivateKeyEntry>> privateKeyEntrySet = privateKeyEntries.entrySet();
		for (KeyStoreAlias keyStoreAlias : selfSignedTrusted) {
			String keyStoreId = contactIndex.findByKeyStoreAlias(keyStoreAlias);
			KeyStoreWraper keyStore = loadKeyStore(keyStoreId);
			if(keyStore==null) continue;
			TrustedCertificateEntry trustedCertificateEntry = keyStore.findEntryByAlias(TrustedCertificateEntry.class, keyStoreAlias);
			// find the corresponding certificate signed by one of my private keys 
			// in that store
			for (Map.Entry<KeyStoreAlias, PrivateKeyEntry> entry : privateKeyEntrySet) {
				KeyStoreAlias privateKeyAlias = entry.getKey();
				KeyStoreAlias signedByme = new KeyStoreAlias(keyStoreAlias.getPublicKeyIdHex(), keyStoreAlias.getSubjectKeyIdHex(), 
						privateKeyAlias.getSubjectKeyIdHex(), null,TrustedCertificateEntry.class);
				TrustedCertificateEntry certSignedByme = keyStore.findEntryByAlias(TrustedCertificateEntry.class, signedByme);
				if(certSignedByme!=null){
					try {
						certSignedByme.getTrustedCertificate().verify(entry.getValue().getCertificate().getPublicKey());
						trustedCertificateEntries.add(trustedCertificateEntry);					
					} catch (Exception e) {
						// ignore certificate
					}
				}
			}
		}
		
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		for (Map.Entry<KeyStoreAlias, PrivateKeyEntry> entry : privateKeyEntrySet) {
			trustAnchors.add(new TrustAnchor((X509Certificate) entry.getValue().getCertificate(), null));
		}
		for (TrustedCertificateEntry entry : trustedCertificateEntries) {
			trustAnchors.add(new TrustAnchor((X509Certificate) entry.getTrustedCertificate(), null));
		}

		return trustAnchors;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCertStores(org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public Set<CertStore> findCertStores(X509CertificateHolder... certificates) {
		return findCertStores(Arrays.asList(certificates));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCertStores(java.util.List)
	 */
	@Override
	public Set<CertStore> findCertStores(List<X509CertificateHolder> certificates) {
		List<X509CertificateHolder> researchList = KeyStoreWraperUtils.dropCertWithIncludedCa(certificates);
		List<X509CertificateHolder> signerCerts = new ArrayList<X509CertificateHolder>();
		signed: for (X509CertificateHolder signedCertificate : researchList) {
			X500Name subject = signedCertificate.getSubject();
			List<PrivateKeyEntry> privateCaEntries = findCaEntriesBySubject(PrivateKeyEntry.class, subject);
			for (PrivateKeyEntry privateKeyEntry : privateCaEntries) {
				X509CertificateHolder signerCertificate = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
				if (V3CertificateUtils.isSigingCertificate(signedCertificate, signerCertificate)){
					if(!signerCerts.contains(signerCertificate))signerCerts.add(signerCertificate);
					break signed;
				}
			}
			List<TrustedCertificateEntry> trusted = findCaEntriesBySubject(TrustedCertificateEntry.class, subject);
			for (TrustedCertificateEntry trustedCertificateEntry : trusted) {
				X509CertificateHolder signerCertificate = V3CertificateUtils.getX509CertificateHolder(trustedCertificateEntry.getTrustedCertificate());
				if (V3CertificateUtils.isSigingCertificate(signedCertificate, signerCertificate)){
					if(!signerCerts.contains(signerCertificate))signerCerts.add(signerCertificate);
					break signed;
				}
			}
		}
		if(signerCerts.isEmpty()) return Collections.emptySet();
		CertStore certStore = V3CertificateUtils.createCertStore(signerCerts);
		HashSet<CertStore> hashSet = new HashSet<CertStore>();
		hashSet.add(certStore);
		Set<CertStore> foundCertStores = findCertStores(signerCerts);
		if(foundCertStores!=null)hashSet.addAll(foundCertStores);
		return hashSet;
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#isAuthenticated()
	 */
	@Override
	public boolean isAuthenticated(){
		return mainKeyStoreWraper.isAuthenticated();
	}

	@Override
	public X509CRL getCrl() {
		return null;
	}

	@Override
	public PrivateKeyEntry getMainMessagePrivateKeyEntry() {
		List<KeyStoreAlias> keyStoreAliases = mainKeyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class)) {
				PrivateKeyEntry privateKeyEntry = mainKeyStoreWraper.findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
				Certificate certificate = privateKeyEntry.getCertificate();
				if(V3CertificateUtils.isSmimeKey(certificate)) return privateKeyEntry;
			}
		}
		return null;
	}

	@Override
	public PrivateKeyEntry getMainCaPrivateKeyEntry() {
		List<KeyStoreAlias> keyStoreAliases = mainKeyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class)) {
				PrivateKeyEntry privateKeyEntry = mainKeyStoreWraper.findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
				Certificate certificate = privateKeyEntry.getCertificate();
				if(V3CertificateUtils.isCaKey(certificate)) return privateKeyEntry;
			}
		}
		return null;
	}

	@Override
	public Set<String> listContacts() {
		return contactIndex.listEmailContacts();
	}
}
