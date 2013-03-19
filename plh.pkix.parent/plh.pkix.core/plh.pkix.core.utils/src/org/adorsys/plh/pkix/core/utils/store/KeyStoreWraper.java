package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * Holds a key store in memory and manages access to the key store.
 * 
 * @author francis
 *
 */
public class KeyStoreWraper {

	private final KeyStore keyStore;
	private final FileWrapper keyStoreFile;
	private final char[] storePass;

	private char[] keyPass;
	private ProtectionParameter protParam;
	
	public KeyStoreWraper(FileWrapper keyStoreFile, char[] keyPass, char[] storePass) {
		this.keyStore = KeyStoreWraperUtils.instance(storePass);
		this.keyStoreFile = keyStoreFile;
		this.keyPass = keyPass;
		if(keyPass!=null)
			protParam = new KeyStore.PasswordProtection(keyPass);
		this.storePass = storePass;
		if(this.keyStoreFile!=null && this.keyStoreFile.exists())
			KeyStoreWraperUtils.load(keyStoreFile, keyStore, storePass);
	}
	
	/**
	 * Set the key pass
	 * @param keyPass
	 */
	public void setKeyPass(char[] keyPass) {
		this.keyPass = keyPass;
		if(keyPass!=null)
			protParam = new KeyStore.PasswordProtection(keyPass);
	}

	@SuppressWarnings("unchecked")
	public <T extends Entry> T findMessageEntryByEmail(Class<T> klass,
			String... emails) {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				Entry entry = getEntry(alias);
				if(entry==null) continue;
				if(entry.getClass()!=klass)continue;
				java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
				List<String> subjectEmails = X500NameHelper.readSubjectEmails(certificate);
				
				for (String email : emails) {
					if(subjectEmails.contains(email)) return (T)entry; 
				}
			}
			return null;
		} catch (KeyStoreException e){
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	@SuppressWarnings("unchecked")
	public <T extends Entry> List<T> findMessageEntriesByEmail(Class<T> klass,
			String... emails) {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			List<T> result = new ArrayList<T>();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				Entry entry = getEntry(alias);
				if(entry==null) continue;
				if(entry.getClass()!=klass)continue;
				java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
				List<String> subjectEmails = X500NameHelper.readSubjectEmails(certificate);
				for (String email : emails) {
					if(subjectEmails.contains(email)) result .add((T)entry); 
				}
			}
			return result;
		} catch (KeyStoreException e){
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	@SuppressWarnings("unchecked")
	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases) {
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			Entry entry = getEntry(keyStoreAlias.getAlias());
			if(entry==null) continue;
			if(entry.getClass()!=klass) continue;
			return (T) entry;				
		}
		return null;
	}

	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntryByAlias(klass, Arrays.asList(keyStoreAliases));
	}
	
	@SuppressWarnings("unchecked")
	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,List<KeyStoreAlias> keyStoreAliases) {
		List<T> result = new ArrayList<T>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			Entry entry = getEntry(keyStoreAlias.getAlias());
			if(entry==null) continue;
			if(entry.getClass()!=klass) continue;
			result.add( (T) entry);				
		}
		return result;
	}

	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntriesByAlias(klass, Arrays.asList(keyStoreAliases));
	}

	public Enumeration<String> aliases() {
		try {
			return keyStore.aliases();
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	public List<KeyStoreAlias> keyStoreAliases() {
		List<KeyStoreAlias> result = new ArrayList<KeyStoreAlias>();
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				result.add(new KeyStoreAlias(alias));
			}
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
		return result;
	}

	public void importCertificates(Certificate... certArray)
			throws PlhCheckedException {
		java.security.cert.Certificate[] chain = new java.security.cert.Certificate[certArray.length];
		KeyStoreAlias[] keyAliases = new KeyStoreAlias[certArray.length];
		X509CertificateHolder[] holderChain = new X509CertificateHolder[certArray.length];
		for (int i = 0; i < certArray.length; i++) {
			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
			holderChain[i]=new X509CertificateHolder(certificate);
		}
		
		for (int i = 0; i < certArray.length; i++) {
			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate);
			keyAliases[i]=new KeyStoreAlias(x509CertificateHolder, TrustedCertificateEntry.class);
			
			// We keep the key store certificate if existing .
			if(containsAlias(keyAliases[i])) {
				chain[i] = getCertificate(keyAliases[i]);

				// recompute holder
				try {
					x509CertificateHolder = new X509CertificateHolder(chain[i].getEncoded());
				} catch (CertificateEncodingException e) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
		            throw new PlhUncheckedException(msg, e);
				} catch (IOException e) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
		            throw new PlhUncheckedException(msg, e);
				}
			} else {
				chain[i] = V3CertificateUtils.getX509JavaCertificate(x509CertificateHolder);
			}
			holderChain[i]=x509CertificateHolder;
			if(i>0){
				ContentVerifierProvider verifierProvider;
				try {
					verifierProvider = new JcaContentVerifierProviderBuilder()
						.setProvider(ProviderUtils.bcProvider)
						.build(holderChain[i]);
				} catch (OperatorCreationException e) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_certVerifyException,
		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
		            throw new PlhUncheckedException(msg, e);
				} catch (CertificateException e1) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidCertificate,
		                    new Object[] { holderChain[i].getSubject(), holderChain[i].getIssuer() , holderChain[i].getSerialNumber()});
		            throw new PlhCheckedException(msg);
				}
				boolean signatureValid;
				try {
					signatureValid = holderChain[i-1].isSignatureValid(verifierProvider);
				} catch (CertException e) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_certVerifyException,
		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
		            throw new PlhUncheckedException(msg, e);
				}
				if(!signatureValid){
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidSignature,
		                    new Object[] { holderChain[i-1].getSubject(), holderChain[i-1].getIssuer() , holderChain[i-1].getSerialNumber(), holderChain[i].getSerialNumber()});
		            throw new PlhCheckedException(msg);
				}
			}
		}
		
		for (int i = 0; i < chain.length; i++) {
			java.security.cert.Certificate certificate = chain[i];
			KeyStoreAlias keyAlias = keyAliases[i];
			try {
				keyStore.setCertificateEntry(keyAlias.getAlias(), certificate);
			} catch (KeyStoreException e) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
	            throw new PlhUncheckedException(msg, e);
			}
		}
		store();
	}

	/**
	 * Import a issued certificate. We assume that the passed in private key entry is the entry for
	 * which the certificate has been issued.
	 * 
	 * @param privateKeyEntry
	 * @param certArray
	 * @throws PlhCheckedException 
	 */
	public void importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
		// do no process empty inputs
		if(certArray.length<=0) return;
		
		java.security.cert.Certificate[] chain = new java.security.cert.Certificate[certArray.length];
		X509CertificateHolder[] certificateHolderChain = new X509CertificateHolder [certArray.length];
		for (int i = 0; i < certArray.length; i++) {
			certificateHolderChain[i] = new X509CertificateHolder(certArray[i]);
			chain[i] = V3CertificateUtils.getX509JavaCertificate(certificateHolderChain[i]);
		}
		//get the associated private key from the key store
		List<KeyStoreAlias> existingAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(aliases(), certificateHolderChain[0]);
		PrivateKeyEntry privateKeyEntry = null;
		for (KeyStoreAlias keyStoreAlias : existingAliases) {
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class))
					privateKeyEntry = (PrivateKeyEntry) getEntry(keyStoreAlias.getAlias());
		}

		if(privateKeyEntry==null){
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_missingPrivateKeyEntry,
                    new Object[] { certificateHolderChain[0].getSubject(), certificateHolderChain[0].getIssuer() , certificateHolderChain[0].getSerialNumber()});
            throw new PlhCheckedException(msg);
		}

		KeyStoreAlias newKeyAlias = new KeyStoreAlias(certificateHolderChain[0], PrivateKeyEntry.class);
		try {
			keyStore.setKeyEntry(newKeyAlias.getAlias(), privateKeyEntry.getPrivateKey(), keyPass, chain);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}		
		store();
	}
	
	private boolean containsAlias(KeyStoreAlias alias) {
		try {
			return keyStore.containsAlias(alias.getAlias());
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	private java.security.cert.Certificate getCertificate(KeyStoreAlias alias) {
		try {
			return keyStore.getCertificate(alias.getAlias());
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	
	public void setPrivateKeyEntry(Key key,java.security.cert.Certificate[] chain) {
		try {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(chain[0]);
			String alias = new KeyStoreAlias(certificateHolder, PrivateKeyEntry.class).getAlias();			
			keyStore.setKeyEntry(alias, key, keyPass, chain);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
		store();
	}

	@SuppressWarnings("unchecked")
	public <T extends Entry> T findCaEntry(Class<T> klass, X500Name... subjects){
		try {
			for (X500Name subject : subjects) {
				Enumeration<String> aliases = keyStore.aliases();
				while (aliases.hasMoreElements()) {
					String alias = (String) aliases.nextElement();
					Entry entry = getEntry(alias);
					if(entry==null) continue;
					if(entry.getClass()!=klass) continue;
					java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
					if(certificate==null) continue;
					X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
					if(!subject.equals(certHolder.getSubject())) continue;
					if(!V3CertificateUtils.isCaKey(certificate)) continue;
					return (T) entry;
				}
			}
			return null;
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	@SuppressWarnings("unchecked")
	public <T extends Entry> List<T> findCaEntries(Class<T> klass, X500Name... subjects){
		List<T> r = new ArrayList<T>();
		try {
			for (X500Name subject : subjects) {
				Enumeration<String> aliases = keyStore.aliases();
				while (aliases.hasMoreElements()) {
					String alias = (String) aliases.nextElement();
					Entry entry = getEntry(alias);
					if(entry==null) continue;
					if(entry.getClass()!=klass) continue;
					java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
					if(certificate==null) continue;
					X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
					if(!subject.equals(certHolder.getSubject())) continue;
					if(!V3CertificateUtils.isCaKey(certificate)) continue;
					r.add((T) entry);
				}
			}
			return r;
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	private void store(){
		if(keyStoreFile==null) return;
		OutputStream outputStream = keyStoreFile.newOutputStream();
		try {
			keyStore.store(outputStream, storePass);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (NoSuchAlgorithmException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (CertificateException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (IOException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} finally {
			IOUtils.closeQuietly(outputStream);
		}
	}
	
	private KeyStore.Entry getEntry(String alias){
		try {
			return keyStore.getEntry(alias, protParam);
		} catch (NoSuchAlgorithmException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (UnrecoverableEntryException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	public boolean isAuthenticated() {
		if (keyPass == null)
			return false;
		try {
			findEntryByAlias(PrivateKeyEntry.class, keyStoreAliases());
			return true;
		} catch (Exception ex) {
			return false;
		}
	}
	
	private String randomId = null;
	public String getId(){
		if(keyStoreFile!=null)
			return keyStoreFile.getName();
		if(randomId!=null) return randomId;
		return randomId=UUID.randomUUID().toString();
	}
}
