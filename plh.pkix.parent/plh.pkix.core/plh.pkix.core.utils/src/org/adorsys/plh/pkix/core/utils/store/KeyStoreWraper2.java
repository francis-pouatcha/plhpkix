package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
public class KeyStoreWraper2 {
//
//	public static final String KEYSTORETYPE_STRING = "PKCS12";	
//	
//	private final KeyStore keyStore;
//	private final FileWrapper keyStoreFile;
//	private final char[] storePass;
//
//	private char[] keyPass;
//	private ProtectionParameter protParam;
//	
//	public KeyStoreWraper2(FileWrapper keyStoreFile, char[] keyPass, char[] storePass) {
//		this.keyStore = instance(storePass);
//		this.keyStoreFile = keyStoreFile;
//		this.keyPass = keyPass;
//		if(keyPass!=null)
//			protParam = new KeyStore.PasswordProtection(keyPass);
//		this.storePass = storePass;
//		if(this.keyStoreFile!=null && this.keyStoreFile.exists())
//			load();
//	}
//	
//	/**
//	 * Set the key pass
//	 * @param keyPass
//	 */
//	public void setKeyPass(char[] keyPass) {
//		this.keyPass = keyPass;
//		if(keyPass!=null)
//			protParam = new KeyStore.PasswordProtection(keyPass);
//	}
//
//	/**
//	 * return the private key entry with the corresponding certificate's serial
//	 * number.
//	 * 
//	 * This key store will enforce the unique serial number policy.
//	 * 
//	 * @return
//	 */
//	public PrivateKeyEntry findPrivateKeyEntryBySerialNumber(BigInteger serialNumber) {
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectBySerialNumber(aliases(), serialNumber);
//		if(foundAliases.isEmpty())return null;
//		return findPrivateKeyEntry(foundAliases);
//	}
//	
//	public KeyStore.Entry findEntryBySerialNumber(BigInteger serialNumber) {
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectBySerialNumber(aliases(), serialNumber);
//		if(foundAliases.isEmpty())return null;
//		return findEntry(foundAliases);
//	}
//	
//	public Enumeration<String> aliases() {
//		try {
//			return keyStore.aliases();
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//	public List<KeyStoreAlias> keyStoreAliases() {
//		try {
//			Enumeration<String> aliases = keyStore.aliases();
//			List<KeyStoreAlias> result = new ArrayList<KeyStoreAlias>();
//			while (aliases.hasMoreElements()) {
//				String alias = (String) aliases.nextElement();
//				result.add(new KeyStoreAlias(alias));
//			}
//			return result;
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	public boolean isKeyEntry(String alias) {
//		try {
//			return keyStore.isKeyEntry(alias);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//	
//	public boolean containsAlias(KeyStoreAlias alias) {
//		try {
//			return keyStore.containsAlias(alias.getAlias());
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	public boolean isCertificateEntry(String alias) {
//		try {
//			return keyStore.isCertificateEntry(alias);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	public Certificate getCertificate(KeyStoreAlias alias) {
//		try {
//			return keyStore.getCertificate(alias.getAlias());
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	/**
//	 * Import a issued certificate. We assume that the passed in private key entry is the entry for
//	 * which the certificate has been issued.
//	 * 
//	 * @param privateKeyEntry
//	 * @param certArray
//	 * @throws PlhCheckedException 
//	 */
//	public void importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
//		// do no process empty inputs
//		if(certArray.length<=0) return;
//		
//		Certificate[] chain = new Certificate[certArray.length];
//		X509CertificateHolder[] certificateHolderChain = new X509CertificateHolder [certArray.length];
//		for (int i = 0; i < certArray.length; i++) {
//			certificateHolderChain[i] = new X509CertificateHolder(certArray[i]);
//			chain[i] = V3CertificateUtils.getX509JavaCertificate(certificateHolderChain[i]);
//		}
//		//get the associated private key from the key store
//		List<KeyStoreAlias> existingAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(aliases(), certificateHolderChain[0]);
//		PrivateKeyEntry privateKeyEntry = findPrivateKeyEntry(existingAliases);
//		if(privateKeyEntry==null){
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_certImport_missingPrivateKeyEntry,
//                    new Object[] { certificateHolderChain[0].getSubject(), certificateHolderChain[0].getIssuer() , certificateHolderChain[0].getSerialNumber()});
//            throw new PlhCheckedException(msg);
//		}
//
//		KeyStoreAlias newKeyAlias = new KeyStoreAlias(certificateHolderChain[0]);
//		try {
//			keyStore.setKeyEntry(newKeyAlias.getAlias(), privateKeyEntry.getPrivateKey(), keyPass, chain);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}		
//		store();
//	}
//	
//	/**
//	 * Import trusted certificates. Generally the only certificate supposed to be trusted is the first one.
//	 * We assume the certificate at n signs the one at n-1 and that the last certificate is a root. If one of
//	 * those certificates is already in the system it will not be imported.
//	 * 
//	 * @param certArray
//	 * @throws PlhCheckedException 
//	 */
//	public void importCertificates(
//			org.bouncycastle.asn1.x509.Certificate... certArray) throws PlhCheckedException {
//
//		Certificate[] chain = new Certificate[certArray.length];
//		KeyStoreAlias[] keyAliases = new KeyStoreAlias[certArray.length];
//		X509CertificateHolder[] holderChain = new X509CertificateHolder[certArray.length];
//		for (int i = 0; i < certArray.length; i++) {
//			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
//			holderChain[i]=new X509CertificateHolder(certificate);
//		}
//		
//		for (int i = 0; i < certArray.length; i++) {
//			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
//			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate);
//			keyAliases[i]=new KeyStoreAlias(x509CertificateHolder);
//			
//			// We keep the key store certificate if existing .
//
//			if(containsAlias(keyAliases[i])) {
//				chain[i] = getCertificate(keyAliases[i]);
//
//				// recompute holder
//				try {
//					x509CertificateHolder = new X509CertificateHolder(chain[i].getEncoded());
//				} catch (CertificateEncodingException e) {
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
//		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//		            throw new PlhUncheckedException(msg, e);
//				} catch (IOException e) {
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
//		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//		            throw new PlhUncheckedException(msg, e);
//				}
//			} else {
//				chain[i] = V3CertificateUtils.getX509JavaCertificate(x509CertificateHolder);
//			}
//			holderChain[i]=x509CertificateHolder;
//			if(i>0){
//				ContentVerifierProvider verifierProvider;
//				try {
//					verifierProvider = new JcaContentVerifierProviderBuilder()
//						.setProvider(ProviderUtils.bcProvider)
//						.build(holderChain[i]);
//				} catch (OperatorCreationException e) {
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_certVerifyException,
//		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//		            throw new PlhUncheckedException(msg, e);
//				} catch (CertificateException e1) {
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidCertificate,
//		                    new Object[] { holderChain[i].getSubject(), holderChain[i].getIssuer() , holderChain[i].getSerialNumber()});
//		            throw new PlhCheckedException(msg);
//				}
//				boolean signatureValid;
//				try {
//					signatureValid = holderChain[i-1].isSignatureValid(verifierProvider);
//				} catch (CertException e) {
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_certVerifyException,
//		                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//		            throw new PlhUncheckedException(msg, e);
//				}
//				if(!signatureValid){
//		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidSignature,
//		                    new Object[] { holderChain[i-1].getSubject(), holderChain[i-1].getIssuer() , holderChain[i-1].getSerialNumber(), holderChain[i].getSerialNumber()});
//		            throw new PlhCheckedException(msg);
//				}
//			}
//		}
//		
//		for (int i = 0; i < chain.length; i++) {
//			Certificate certificate = chain[i];
//			KeyStoreAlias keyAlias = keyAliases[i];
//			try {
//				keyStore.setCertificateEntry(keyAlias.getAlias(), certificate);
//			} catch (KeyStoreException e) {
//	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
//	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//	            throw new PlhUncheckedException(msg, e);
//			}
//		}
//		store();
//	}
//
//	public PrivateKeyEntry findPrivateKeyEntryByPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo){
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectByPublicKeyIdentifier(aliases(), subjectPublicKeyInfo);
//		return findPrivateKeyEntry(foundAliases);
//	}
//
//	public KeyStore.Entry findEntryByPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo){
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectByPublicKeyIdentifier(aliases(), subjectPublicKeyInfo);
//		return findEntry(foundAliases);
//	}
//	
//	public KeyStore.Entry findEntryByPublicKeyIdentifier(byte[] publicKeyIdentifier){
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectByPublicKeyIdentifier(aliases(), publicKeyIdentifier);
//		return findEntry(foundAliases);
//	}
//	
//	public PrivateKeyEntry findPrivateKeyEntryByPublicKeyIdentifier(byte[] publicKeyIdentifier){
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectByPublicKeyIdentifier(aliases(), publicKeyIdentifier);
//		return findPrivateKeyEntry(foundAliases);
//	}
//
//	public PrivateKeyEntry findMessagePrivateKeyEntryByIssuerCertificate(X509CertificateHolder issuerCertificate) {
//		Enumeration<String> aliases = aliases();
//		List<KeyStoreAlias> foundAliases = KeyStoreAlias.selectByIssuerKeyIdentifier(aliases, issuerCertificate);
//		return selectMessagePrivateKeyEntry(foundAliases);
//	}
//	
//	public PrivateKeyEntry findAnyMessagePrivateKeyEntry() {
//		Enumeration<String> aliases = aliases();
//		List<KeyStoreAlias> foundAliases = new ArrayList<KeyStoreAlias>();
//		while (aliases.hasMoreElements()) {
//			foundAliases.add(new KeyStoreAlias((String)aliases.nextElement()));
//		}
//		return selectMessagePrivateKeyEntry(foundAliases);
//	}
//	
//	public PrivateKeyEntry findPrivateKeyEntryBySubjectKeyIdentifier(byte[] subjectKeyIdentifierBytes){
//		List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(aliases(), subjectKeyIdentifierBytes);
//		return findPrivateKeyEntry(keyStoreAliases);
//	}
//
//	public KeyStore.Entry findEntryBySubjectKeyIdentifier(byte[] subjectKeyIdentifierBytes){
//		List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias.selectBySubjectKeyIdentifier(aliases(), subjectKeyIdentifierBytes);
//		return findEntry(keyStoreAliases);
//	}
//
//	private PrivateKeyEntry selectMessagePrivateKeyEntry(List<KeyStoreAlias> foundAliases){
//		for (KeyStoreAlias alias : foundAliases) {
//			PrivateKeyEntry keyEntry = findPrivateKeyEntry(alias);
//			X509CertificateHolder x509CertificateHolder = V3CertificateUtils.getX509CertificateHolder(keyEntry.getCertificate());
//			if(V3CertificateUtils.isSmimeKey(x509CertificateHolder)) return keyEntry;
//		}
//		return null;
//	}
//	private List<PrivateKeyEntry> selectMessagePrivateKeyEntries(List<KeyStoreAlias> foundAliases){
//		List<PrivateKeyEntry> result = new ArrayList<KeyStore.PrivateKeyEntry>();
//		for (KeyStoreAlias alias : foundAliases) {
//			PrivateKeyEntry keyEntry = findPrivateKeyEntry(alias);
//			X509CertificateHolder x509CertificateHolder = V3CertificateUtils.getX509CertificateHolder(keyEntry.getCertificate());
//			if(V3CertificateUtils.isSmimeKey(x509CertificateHolder)) result.add(keyEntry);
//		}
//		return result;
//	}
//
//	public PrivateKeyEntry findAnyCaPrivateKeyEntry() {
//		Enumeration<String> aliases = aliases();
//		List<KeyStoreAlias> foundAliases = new ArrayList<KeyStoreAlias>();
//		while (aliases.hasMoreElements()) {
//			foundAliases.add(new KeyStoreAlias((String)aliases.nextElement()));
//		}
//		return selectCaPrivateKeyEntry(foundAliases);
//	}
//
//	private PrivateKeyEntry selectCaPrivateKeyEntry(List<KeyStoreAlias> foundAliases){
//		for (KeyStoreAlias alias : foundAliases) {
//			PrivateKeyEntry keyEntry = findPrivateKeyEntry(alias);
//			X509CertificateHolder x509CertificateHolder = V3CertificateUtils.getX509CertificateHolder(keyEntry.getCertificate());
//			if(V3CertificateUtils.isCaKey(x509CertificateHolder)) return keyEntry;
//		}
//		return null;
//	}
//	
//	public PrivateKeyEntry findPrivateKeyEntry(List<KeyStoreAlias> keyStoreAliases) {
//		try {
//			for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
//				Entry entry = keyStore.getEntry(keyStoreAlias.getAlias(), protParam);
//				if(entry!=null && entry instanceof PrivateKeyEntry) return (PrivateKeyEntry) entry;				
//			}
//			return null;
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (UnrecoverableEntryException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//	public PrivateKeyEntry findPrivateKeyEntry(KeyStoreAlias...keyStoreAliases) {
//		return findPrivateKeyEntry(Arrays.asList(keyStoreAliases));
//	}
//	public List<PrivateKeyEntry> findPrivateKeyEntries(List<KeyStoreAlias> keyStoreAliases) {
//		List<PrivateKeyEntry> result = new ArrayList<KeyStore.PrivateKeyEntry>();
//		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
//			try {
//					Entry entry = keyStore.getEntry(keyStoreAlias.getAlias(), protParam);
//					if(entry!=null && entry instanceof PrivateKeyEntry) result.add( (PrivateKeyEntry) entry);				
//			} catch (NoSuchAlgorithmException e) {
//	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//	            throw new PlhUncheckedException(msg, e);
//			} catch (UnrecoverableEntryException e) {
//	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//	            throw new PlhUncheckedException(msg, e);
//			} catch (KeyStoreException e) {
//	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//	            throw new PlhUncheckedException(msg, e);
//			}
//		}
//		return result;
//	}
//	public KeyStore.Entry findEntry(List<KeyStoreAlias> keyStoreAliases) {
//		try {
//			for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
//				return keyStore.getEntry(keyStoreAlias.getAlias(), protParam);
//			}
//			return null;
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (UnrecoverableEntryException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//	public KeyStore.Entry findEntry(KeyStoreAlias...keyStoreAliases) {
//		return findEntry(Arrays.asList(keyStoreAliases));
//	}
//	public List<KeyStore.Entry> findEntries(List<KeyStoreAlias> keyStoreAliases) {
//		try {
//			List<Entry> result = new ArrayList<KeyStore.Entry>();
//			for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
//				result.add(keyStore.getEntry(keyStoreAlias.getAlias(), protParam));
//			}
//			return result;
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (UnrecoverableEntryException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	public List<KeyStore.Entry> entries() {
//		return findEntries(keyStoreAliases());
//	}
//	
//	public SecretKeyEntry findKEKEntryByKeyIdentifier(byte[] keyIdentifier) {
//		String keyAlias = KeyStoreAlias.makeKEKAlias(keyIdentifier);
//		Entry entry;
//		try {
//			entry = keyStore.getEntry(keyAlias, protParam);
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (UnrecoverableEntryException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//		if(entry instanceof SecretKeyEntry) return (SecretKeyEntry) entry;
//		return null;
//	}
//	
//	private void load(){
//		if(keyStoreFile==null) return;
//		InputStream inputStream = keyStoreFile.newInputStream();
//		try {
//			keyStore.load(inputStream, storePass);
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (CertificateException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (IOException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} finally {
//			IOUtils.closeQuietly(inputStream);
//		}
//	}
//	
//	private void store(){
//		if(keyStoreFile==null) return;
//		OutputStream outputStream = keyStoreFile.newOutputStream();
//		try {
//			keyStore.store(outputStream, storePass);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (NoSuchAlgorithmException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (CertificateException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} catch (IOException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		} finally {
//			IOUtils.closeQuietly(outputStream);
//		}
//	}
//	
//	public Set<TrustAnchor> getTrustAnchors(){
//		Set<TrustAnchor> hashSet = new HashSet<TrustAnchor>();
//		Enumeration<String> aliases = aliases();
//		while (aliases.hasMoreElements()) {
//			String alias = aliases.nextElement();
//			if (isKeyEntry(alias) || isCertificateEntry(alias)) {
//				Certificate cert = getCertificate(new KeyStoreAlias(alias));
//				if(cert==null) continue;
//				if (cert instanceof X509Certificate)
//					hashSet.add(new TrustAnchor((X509Certificate) cert, null));
//			}
//		}
//		return hashSet;
//	}
//	
//	
//	private static final KeyStore instance(char[] storePass){
//		try {
//			return KeyStore.Builder.newInstance(KEYSTORETYPE_STRING,
//					ProviderUtils.bcProvider, 
//					new KeyStore.PasswordProtection(storePass))
//					.getKeyStore();
//		} catch (KeyStoreException e) {
//	          ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	    		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//	            new Object[] { e.getMessage(), e , e.getClass().getName()});
//	          throw new PlhUncheckedException(msg, e);
//		}
//		
//	}
//
//	public void setKeyEntry(Key key,
//			Certificate[] chain) {
//		try {
//			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(chain[0]);
//			String alias = new KeyStoreAlias(certificateHolder).getAlias();			
//			keyStore.setKeyEntry(alias, key, keyPass, chain);
//		} catch (KeyStoreException e) {
//            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
//                    new Object[] { e.getMessage(), e , e.getClass().getName()});
//            throw new PlhUncheckedException(msg, e);
//		}
//		store();
//	}
//	
//	public List<X509CertificateHolder> loadCertificates(){
//		Enumeration<String> aliases = aliases();
//		List<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
//		while (aliases.hasMoreElements()) {
//			String alias = (String) aliases.nextElement();
//			if(isCertificateEntry(alias)) {
//				Certificate certificate;
//				try {
//					certificate = keyStore.getCertificate(alias);
//				} catch (KeyStoreException e) {
//			          ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//			  	    		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//			  	            new Object[] { e.getMessage(), e , e.getClass().getName()});
//			  	          throw new PlhUncheckedException(msg, e);
//				}
//				X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
//				result .add(certificateHolder);
//			}
//		}
//		return result;
//	}
//
//	public PrivateKeyEntry findPrivateKeyEntry(
//			X509CertificateHolder certificateHolder) {
//		return findPrivateKeyEntry(new KeyStoreAlias(certificateHolder));
//	}
//	
//	public X509CertificateHolder findKeyCertificate(String publicKeyIdentifier) {
//		try {
//			KeyStoreAlias searchAlias = new KeyStoreAlias(publicKeyIdentifier, null, null, null);
//			Enumeration<String> aliases = aliases();
//			while (aliases.hasMoreElements()) {
//				String alias = aliases.nextElement();
//				if(!keyStore.isKeyEntry(alias)) continue;
//				
//				KeyStoreAlias keyStoreAlias = new KeyStoreAlias(alias);
//				if(searchAlias!=null){
//					if(keyStoreAlias.matchAny(searchAlias)){
//						return V3CertificateUtils.getX509CertificateHolder(getCertificate(keyStoreAlias));
//					}
//				} else {
//					return V3CertificateUtils.getX509CertificateHolder(getCertificate(keyStoreAlias));
//				}
//			}
//			return null;
//		} catch(KeyStoreException e){
//	          ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
//	  	    		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
//	  	            new Object[] { e.getMessage(), e , e.getClass().getName()});
//	  	          throw new PlhUncheckedException(msg, e);
//		}
//	}
//
//	public boolean isAuthenticated() {
//		if(keyPass==null) return false;
//		try {
//			PrivateKeyEntry pk = findAnyMessagePrivateKeyEntry();
//			if(pk!=null) return true;
//			return false;
//		} catch(Exception ex){
//			return false;
//		}
//	}
//
//	public PrivateKeyEntry findMessagePrivateKeyEntryByEmail(String email) {
//		if(email==null) return findAnyMessagePrivateKeyEntry();
//		List<PrivateKeyEntry> privateKeyEntries = selectMessagePrivateKeyEntries(keyStoreAliases());
//		for (PrivateKeyEntry privateKeyEntry : privateKeyEntries) {
//			X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
//			List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
//			if(subjectEmails.contains(email)) return privateKeyEntry;
//		}
//		return null;
//	}
//
//	public PrivateKeyEntry findMessagePrivateKeyEntryBySubject(X500Name subject) {
//		if(subject==null) return findAnyMessagePrivateKeyEntry();
//		List<PrivateKeyEntry> privateKeyEntries = selectMessagePrivateKeyEntries(keyStoreAliases());
//		for (PrivateKeyEntry privateKeyEntry : privateKeyEntries) {
//			X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
//			X500Name subjectDN = X500NameHelper.readSubjectDN(certHolder);
//			if(subject.equals(subjectDN)) return privateKeyEntry;
//		}
//		return null;
//	}
}
