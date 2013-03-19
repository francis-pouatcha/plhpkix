package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;

public class KeyStoreWraperUtils {
	public static final String KEYSTORETYPE_STRING = "PKCS12";	

	static final void load(FileWrapper keyStoreFile, KeyStore keyStore, char[] storePass){
		if(keyStoreFile==null) return;
		InputStream inputStream = keyStoreFile.newInputStream();
		try {
			keyStore.load(inputStream, storePass);
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
			IOUtils.closeQuietly(inputStream);
		}
	}
	
	static final void store(FileWrapper keyStoreFile, KeyStore keyStore, char[] storePass){
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
	
	static final KeyStore instance(char[] storePass){
		try {
			return KeyStore.Builder.newInstance(KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection(storePass))
					.getKeyStore();
		} catch (KeyStoreException e) {
	          ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	    		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
	            new Object[] { e.getMessage(), e , e.getClass().getName()});
	          throw new PlhUncheckedException(msg, e);
		}
		
	}
	
	static Enumeration<String> aliases(KeyStore keyStore) {
		try {
			return keyStore.aliases();
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	static boolean isKeyEntry(String alias, KeyStore keyStore) {
		try {
			return keyStore.isKeyEntry(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	static boolean isCertificateEntry(String alias, KeyStore keyStore) {
		try {
			return keyStore.isCertificateEntry(alias);
		} catch (KeyStoreException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.KeyStoreWraper_read_keystoreException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	public static List<X509CertificateHolder> dropCertWithIncludedCa(List<X509CertificateHolder> certificates){
		Map<KeyStoreAlias, X509CertificateHolder> keyStoreAliases = new HashMap<KeyStoreAlias, X509CertificateHolder>();
		Vector<String> aliases = new Vector<String>();
		for (X509CertificateHolder x509CertificateHolder : certificates) {
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(x509CertificateHolder, null);
			keyStoreAliases.put(keyStoreAlias,x509CertificateHolder);
			aliases.add(keyStoreAlias.getAlias());
		}
		Enumeration<String> aliasEnum = aliases.elements();
		// eliminate certs whose ca are included in the input and certs which
		// are self signed
		List<X509CertificateHolder> certWithCa = new ArrayList<X509CertificateHolder>();
		for (X509CertificateHolder x509CertificateHolder : certificates) {
			String caSubjectKeyId = KeyIdUtils.readAuthorityKeyIdentifierAsString(x509CertificateHolder);
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, caSubjectKeyId, null, null,null);
			List<KeyStoreAlias> cas = KeyStoreAlias.select(aliasEnum, keyStoreAlias);
			if(cas.isEmpty())certWithCa.add(x509CertificateHolder);
		}
		ArrayList<X509CertificateHolder> researchList = new ArrayList<X509CertificateHolder>(certificates);
		researchList.removeAll(certWithCa);
		return researchList;
	}
	

}
