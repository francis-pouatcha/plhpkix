package org.adorsys.plh.pkix.core.smime.utils;

import java.security.KeyStore.SecretKeyEntry;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class SecretKeySelector {

	KeyStoreWraper keyStoreWraper;
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public SecretKeyEntry select(){
		checker.checkDirty()
			.checkNull(recipient, keyStoreWraper);

        RecipientId recipientId = recipient.getRID();

        if(!(recipientId instanceof KEKRecipientId))
        	return null;

        KEKRecipientId kekRecipientId = (KEKRecipientId) recipientId;
    	byte[] keyIdentifier = kekRecipientId.getKeyIdentifier();
    	return keyStoreWraper.findKEKEntryByKeyIdentifier(keyIdentifier);
	}

	public SecretKeySelector withRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}

	public SecretKeySelector withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}
}
