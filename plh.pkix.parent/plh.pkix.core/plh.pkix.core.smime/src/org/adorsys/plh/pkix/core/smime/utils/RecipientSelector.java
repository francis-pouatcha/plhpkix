package org.adorsys.plh.pkix.core.smime.utils;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.util.Collection;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

public class RecipientSelector {
	private Collection<RecipientInformation> recipientInfosColection; 
	private KeyStoreWraper keyStoreWraper;
	
	private final BuilderChecker checker = new BuilderChecker(RecipientSelector.class);
	public RecipientAndRecipientInfo select(){
		checker.checkDirty().checkNull(keyStoreWraper, recipientInfosColection)
			.checkEmpty(recipientInfosColection);
        RecipientInformation recipientInformation = null;
        PrivateKeyEntry privateKeyEntry = null;
        SecretKeyEntry secretKeyEntry = null;

        for (RecipientInformation recipientInfo : recipientInfosColection) {
            recipientInformation = recipientInfo;
            RecipientId recipientId = recipientInformation.getRID();
            if(recipientId instanceof KeyTransRecipientId){
                privateKeyEntry = new PrivateKeySelector()
            	.withKeyStoreWraper(keyStoreWraper)
            	.withRecipientInformation(recipientInformation)
            	.select();
            } else if (recipientId instanceof KEKRecipientId){
            	secretKeyEntry = new SecretKeySelector()
            	.withKeyStoreWraper(keyStoreWraper)
            	.withRecipientInformation(recipientInformation)
            	.select();
            }
            if(privateKeyEntry!=null || secretKeyEntry!=null) break;
		}

        if(recipientInformation==null || (privateKeyEntry==null && secretKeyEntry==null)) throw new SecurityException("No matching private key or secret key found for recipients of this file");
        
        Recipient recipient = null;
        if(privateKeyEntry!=null){
        	recipient = new JceKeyTransEnvelopedRecipient(privateKeyEntry.getPrivateKey()).setProvider(ProviderUtils.bcProvider);
        } else if(secretKeyEntry!=null){
        	recipient = new JceKEKEnvelopedRecipient(secretKeyEntry.getSecretKey()).setProvider(ProviderUtils.bcProvider);
        }
        
        return new RecipientAndRecipientInfo(recipientInformation, recipient);
	}
	public RecipientSelector withRecipientInfosColection(
			Collection<RecipientInformation> recipientInfosColection) {
		this.recipientInfosColection = recipientInfosColection;
		return this;
	}
	public RecipientSelector withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}
	
	
}
