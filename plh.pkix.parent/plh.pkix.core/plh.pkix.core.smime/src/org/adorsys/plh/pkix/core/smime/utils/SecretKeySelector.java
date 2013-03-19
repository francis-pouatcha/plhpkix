package org.adorsys.plh.pkix.core.smime.utils;

import java.security.KeyStore.SecretKeyEntry;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class SecretKeySelector {

	private ContactManager contactManager;
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public SecretKeyEntry select(){
		checker.checkDirty()
			.checkNull(recipient, contactManager);

        RecipientId recipientId = recipient.getRID();

        if(!(recipientId instanceof KEKRecipientId))
        	return null;

    	return contactManager.findEntryByPublicKeyIdentifier(SecretKeyEntry.class, 
    			((KEKRecipientId) recipientId).getKeyIdentifier());
	}

	public SecretKeySelector withRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}
	public SecretKeySelector withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
