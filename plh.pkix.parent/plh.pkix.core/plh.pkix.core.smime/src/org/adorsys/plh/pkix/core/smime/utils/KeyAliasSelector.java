package org.adorsys.plh.pkix.core.smime.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyAliasUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class KeyAliasSelector {

	private List<String> aliases = new ArrayList<String>();
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public String select(){
		checker.checkDirty()
			.checkNull(recipient)
			.checkEmpty(aliases);

        RecipientId recipientId = recipient.getRID();
        if(recipientId instanceof KeyTransRecipientId){
            KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
            byte[] subjectKeyIdentifier = keyTransRecipientId.getSubjectKeyIdentifier();
            if(subjectKeyIdentifier!=null){
            	return KeyAliasUtils.selectBySubjectKeyIdentifier(aliases, subjectKeyIdentifier);
            } else {
                BigInteger serialNumber = keyTransRecipientId.getSerialNumber();
                return KeyAliasUtils.selectBySerialNumber(aliases, serialNumber);
            }
        } else if(recipientId instanceof KEKRecipientId) {
        	KEKRecipientId kekRecipientId = (KEKRecipientId) recipientId;
        	byte[] keyIdentifier = kekRecipientId.getKeyIdentifier();
            if(keyIdentifier!=null)
            	return KeyAliasUtils.selectBySubjectKeyIdentifier(aliases, keyIdentifier);
        }
        
        return null;
	}
	
	public KeyAliasSelector addAliases(Collection<String> aliases) {
		this.aliases.addAll(aliases);
		return this;
	}

	public KeyAliasSelector setRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}
	
	
}
