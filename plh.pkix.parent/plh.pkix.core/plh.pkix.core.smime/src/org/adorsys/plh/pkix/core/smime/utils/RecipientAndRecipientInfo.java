package org.adorsys.plh.pkix.core.smime.utils;

import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;

public class RecipientAndRecipientInfo {

    private final RecipientInformation recipientInformation;
    private final Recipient recipient;
	public RecipientAndRecipientInfo(RecipientInformation recipientInformation,
			Recipient recipient) {
		super();
		this.recipientInformation = recipientInformation;
		this.recipient = recipient;
	}
	public RecipientInformation getRecipientInformation() {
		return recipientInformation;
	}
	public Recipient getRecipient() {
		return recipient;
	}
}
