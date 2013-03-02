package org.adorsys.plh.pkix.core.smime.utils;

import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class PrivateKeySelector {

	KeyStoreWraper keyStoreWraper;
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public PrivateKeyEntry select(){
		checker.checkDirty()
			.checkNull(recipient, keyStoreWraper);

        RecipientId recipientId = recipient.getRID();
        if(!(recipientId instanceof KeyTransRecipientId))
        	return null;
        	
        KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
        byte[] subjectKeyIdentifier = keyTransRecipientId.getSubjectKeyIdentifier();
        if(subjectKeyIdentifier!=null){
        	PrivateKeyEntry pk = keyStoreWraper.findPrivateKeyEntryBySubjectKeyIdentifier(subjectKeyIdentifier);
        	if(pk!=null) return pk;
        }
        
        BigInteger serialNumber = keyTransRecipientId.getSerialNumber();
        return keyStoreWraper.findPrivateKeyEntryBySerialNumber(serialNumber);
	}

	public PrivateKeySelector withRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}

	public PrivateKeySelector withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}
}
