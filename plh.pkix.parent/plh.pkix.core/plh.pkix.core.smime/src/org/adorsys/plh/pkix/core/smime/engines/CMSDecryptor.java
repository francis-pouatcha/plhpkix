package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.adorsys.plh.pkix.core.smime.utils.KeyAliasSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

public class CMSDecryptor {
	KeyStore keyStore;
	CMSPart inputPart;
	CallbackHandler callbackHandler;
	
	private final BuilderChecker checker = new BuilderChecker(CMSDecryptor.class);
	public CMSPart decrypt() {

		checker.checkDirty()
			.checkNull(keyStore,callbackHandler,inputPart);
		
		CMSEnvelopedDataParser cmsEnvelopedDataParser;
		try {
			InputStream newInputStream = inputPart.newInputStream();
			cmsEnvelopedDataParser = new CMSEnvelopedDataParser(newInputStream);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}

		RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();		

        @SuppressWarnings("rawtypes")
		Collection recipientsColection = recipients.getRecipients();
        RecipientInformation recipient = null;
        PrivateKeyEntry privateKeyEntry = null;
        Map<BigInteger, RecipientInformation> recipientsBySerialNumber =new HashMap<BigInteger, RecipientInformation>();
        Map<byte[], RecipientInformation> recipientsBySubjectKeyId =new HashMap<byte[], RecipientInformation>();
        for (Object object : recipientsColection) {
            recipient = (RecipientInformation)object;
            RecipientId recipientId = recipient.getRID();
            if(!(recipientId instanceof KeyTransRecipientId)) continue;
            
            KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
            recipientsBySubjectKeyId.put(keyTransRecipientId.getSubjectKeyIdentifier(), recipient);
            recipientsBySerialNumber.put(keyTransRecipientId.getSerialNumber(), recipient);
        }        
        
        recipientsBySubjectKeyId.keySet();
        Enumeration<String> aliasesEnum;
		try {
			aliasesEnum = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
        ArrayList<String> aliases = new ArrayList<String>();
        while (aliasesEnum.hasMoreElements()) {
			String string = (String) aliasesEnum.nextElement();
			aliases.add(string);
		}
        for (Object object : recipientsColection) {
            recipient = (RecipientInformation)object;
            RecipientId recipientId = recipient.getRID();
            if(!(recipientId instanceof KeyTransRecipientId)) continue;
            String alias = new KeyAliasSelector()
            	.addAliases(aliases)
            	.setRecipientInformation(recipient)
            	.select();
            try {
            	PasswordCallback passwordCallback = new PasswordCallback("Enter your password", false);
            	callbackHandler.handle(new Callback[]{passwordCallback});
				privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwordCallback.getPassword()));
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			} catch (UnrecoverableEntryException e) {
				throw new SecurityException(e);
			} catch (KeyStoreException e) {
				throw new IllegalStateException(e);
			} catch (UnsupportedCallbackException e) {
				throw new IllegalStateException(e);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);// can not access callback handler
			}
		}

        if(recipient==null || privateKeyEntry==null) throw new SecurityException("No matching private key found for recipients of this file");
        
        InputStream encrryptedContentStream = null;
        try {
        	CMSTypedStream contentStream = recipient.getContentStream(
					new JceKeyTransEnvelopedRecipient(privateKeyEntry.getPrivateKey()).setProvider(ProviderUtils.bcProvider));
        	encrryptedContentStream = contentStream.getContentStream();
        	return CMSPart.instanceFrom(encrryptedContentStream);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {// can not read content stream
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(encrryptedContentStream);
		}
	}
	
	public CMSDecryptor withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}
	public CMSDecryptor withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}
	public CMSDecryptor withCallbackHandler(CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}
}
