package org.adorsys.plh.pkix.core.utils.jca;

import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Enumeration;

import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * Select a private key from the key store based on the subject key identifier.
 * 
 * @author francis
 *
 */
public class KeySelector {

	private KeyStore keyStore;
	
	private byte[] subjectKeyIdentifier;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public PrivateKeyEntry select(CallbackHandler callbackHandler){
		checker.checkDirty().checkNull(keyStore, subjectKeyIdentifier, callbackHandler);
		String keyIdString = new String(Hex.encode(subjectKeyIdentifier));
		Enumeration<String> aliases;
		try {
			aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				if(!keyStore.isKeyEntry(alias)) continue;
				if(StringUtils.startsWithIgnoreCase(alias, keyIdString)) {
					Entry entry = keyStore.getEntry(alias, new KeyStore.CallbackHandlerProtection(callbackHandler));
					if(entry instanceof PrivateKeyEntry)
						return (PrivateKeyEntry) entry;
				}
			}
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);// unloaded keystore
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);// unloaded keystore
		} catch (UnrecoverableEntryException e) {
			throw new SecurityException(e);
		}
		return null;
	}
	
	public KeySelector setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public KeySelector setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
		this.subjectKeyIdentifier = subjectKeyIdentifier;
		return this;
	}
}
