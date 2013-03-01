package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyAliasUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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
	
	private final ProtectionParameter protParam;
	
	private final char[] keyPass;
	
	public KeyStoreWraper(KeyStore keyStore, FileWrapper keyStoreFile, char[] keyPass) {
		this.keyStore = keyStore;
		this.keyStoreFile = keyStoreFile;
		protParam = new KeyStore.PasswordProtection(keyPass);
		this.keyPass = keyPass;
	}

	/**
	 * return the private key entry with the corresponding certificate's serial
	 * number.
	 * 
	 * This key store will enforce the unique serial number policy.
	 * 
	 * @return
	 */
	public PrivateKeyEntry findKeyEntryBySerialNumber(BigInteger serialNumber) {
		Enumeration<String> aliases;
		try {
			aliases = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
		List<String> foundAliases = KeyAliasUtils.selectBySerialNumber(aliases, serialNumber);
		if(foundAliases.isEmpty())return null;
		Entry entry;
		try {
			entry = keyStore.getEntry(foundAliases.iterator().next(), protParam);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (UnrecoverableEntryException e) {
			throw new IllegalStateException(e);
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}

		if(entry instanceof PrivateKeyEntry) return (PrivateKeyEntry) entry;
		return null;
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

	public boolean isKeyEntry(String alias) {
		try {
			return keyStore.isKeyEntry(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	public boolean containsAlias(String alias) {
		try {
			return keyStore.containsAlias(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	public boolean isCertificateEntry(String alias) {
		try {
			return keyStore.isCertificateEntry(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	public Certificate getCertificate(String alias) {
		try {
			return keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	/**
	 * Import a issued certificate. We assume that the passed in private key entry is the entry for
	 * which the certificate has been issued.
	 * 
	 * @param privateKeyEntry
	 * @param certArray
	 * @throws PlhCheckedException 
	 */
	public void importIssuedCertificate(PrivateKeyEntry privateKeyEntry,
			org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
		JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
		Certificate[] chain = new Certificate[certArray.length];
		String keyAlias = null;
		for (int i = 0; i < certArray.length; i++) {
			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
			X509CertificateHolder x509CertificateHolder;
			try {
				x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
			} catch (IOException e) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
	            throw new PlhUncheckedException(msg, e);
			}
			X509Certificate x509Certificate;
			try {
				x509Certificate = jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
			} catch (CertificateException e) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidCertificate,
	                    new Object[] { x509CertificateHolder.getSubject(), 
	            	x509CertificateHolder.getIssuer() , x509CertificateHolder.getSerialNumber()});
	            throw new PlhCheckedException(msg);
			}
			chain[i]=x509Certificate;
			if(i==0) 
				keyAlias = KeyAliasUtils.computeKeyAlias(x509CertificateHolder);
		}
		try {
			keyStore.setKeyEntry(keyAlias, privateKeyEntry.getPrivateKey(), keyPass, chain);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}		
	}
	
	/**
	 * Import trusted certificates. Generally the only certificate supposed to be trusted is the first one.
	 * We assume the certificate at n signs the one at n-1 and that the last certificate is a root. If one of
	 * those certificates is already in the system it will not be imported.
	 * 
	 * @param certArray
	 * @throws PlhCheckedException 
	 */
	public void importCertificates(
			org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
		JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
		Certificate[] chain = new Certificate[certArray.length];
		String[] keyAliases = new String[certArray.length];
		X509CertificateHolder[] holderChain = new X509CertificateHolder[certArray.length];
		for (int i = 0; i < certArray.length; i++) {
			org.bouncycastle.asn1.x509.Certificate certificate = certArray[i];
			X509CertificateHolder x509CertificateHolder;
			try {
				x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
			} catch (IOException e) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_generalCertificateException,
	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
	            throw new PlhUncheckedException(msg, e);
			}
			keyAliases[i]=KeyAliasUtils.computeKeyAlias(x509CertificateHolder);
			
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
				X509Certificate x509Certificate;
				try {
					x509Certificate = jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
				} catch (CertificateException e) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
		            		PlhPkixCoreMessages.KeyStoreWraper_certImport_invalidCertificate,
		                    new Object[] { holderChain[i].getSubject(), holderChain[i].getIssuer() , holderChain[i].getSerialNumber()});
		            throw new PlhCheckedException(msg);
				}
				chain[i]=x509Certificate;
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
			Certificate certificate = chain[i];
			String keyAlias = keyAliases[i];
			try {
				keyStore.setCertificateEntry(keyAlias, certificate);
			} catch (KeyStoreException e) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyStoreWraper_certImport_keystoreException,
	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
	            throw new PlhUncheckedException(msg, e);
			}
		}
	}

	public PrivateKeyEntry getMessageKeyEntryBySubjectKeyId(ASN1OctetString subjectKID) {
		Enumeration<String> aliases = aliases();
		List<String> foundAliases = KeyAliasUtils.selectBySubjectKeyIdentifier(aliases, subjectKID.getOctets());
		for (String alias : foundAliases) {
			PrivateKeyEntry keyEntry = getKeyEntry(alias);
			Certificate certificate = keyEntry.getCertificate();
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
			if(V3CertificateUtils.isSmimeKey(x509CertificateHolder)) return keyEntry;
		}

		return null;
	}

	public PrivateKeyEntry getKeyEntry(String alias) {
		try {
			return (PrivateKeyEntry) keyStore.getEntry(alias, protParam);
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
	
	public PrivateKeyEntry getMessageKeyEntryBySubjectName(X500Name subjectName) {
		KeyAliasUtils.selectByIssuerKeyIdentifier(aliases, certificateHolder)
		return null;
	}

	public PrivateKeyEntry getMessageKeyEntryByIssuerCertificate(X509CertificateHolder issuerCertificate) {
		Enumeration<String> aliases;
		try {
			aliases = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
		String alias = KeyAliasUtils.selectByIssuerKeyIdentifier(aliases, issuerCertificate);
		if(alias==null)return null;
		Entry entry;
		try {
			entry = keyStore.getEntry(alias, protParam);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (UnrecoverableEntryException e) {
			throw new IllegalStateException(e);
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}

		if(entry instanceof PrivateKeyEntry) return (PrivateKeyEntry) entry;
		return null;
	}
	
	public PrivateKeyEntry getAnyMessageKeyEntry() {
		return null;
	}
}
