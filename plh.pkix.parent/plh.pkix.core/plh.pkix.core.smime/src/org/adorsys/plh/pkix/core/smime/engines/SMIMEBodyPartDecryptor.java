package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
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

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.adorsys.plh.pkix.core.smime.utils.KeyAliasSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class SMIMEBodyPartDecryptor {
	private KeyStore keyStore;
	private MimeBodyPart mimeBodyPart;
	private CallbackHandler callbackHandler;
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartDecryptor.class);
	public MimeBodyPart decrypt() {

		checker.checkDirty()
			.checkNull(keyStore,callbackHandler,mimeBodyPart);
		
		SMIMEEnvelopedParser m;
		try {
			m = new SMIMEEnvelopedParser(mimeBodyPart);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		}
		RecipientInformationStore recipients = m.getRecipientInfos();

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
        
        try {
			return SMIMEUtil.toMimeBodyPart(
					recipient.getContentStream(
							new JceKeyTransEnvelopedRecipient(
										privateKeyEntry.getPrivateKey()
							).setProvider(ProviderUtils.bcProvider)));
		} catch (SMIMEException e) {
			throw new SecurityException(e);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public SMIMEBodyPartDecryptor withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public SMIMEBodyPartDecryptor withMimeBodyPart(MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}

	public SMIMEBodyPartDecryptor withCallbackHandler(CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}
}
