package org.adorsys.plh.pkix.core.cmp.stores;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class FetchRequestHolder {

	private PKIMessage lastFetchedMessage;

	public PKIMessage getLastFetchedMessage() {
		return lastFetchedMessage;
	}

	public void setLastFetchedMessage(PKIMessage lastFetchedMessage) {
		this.lastFetchedMessage = lastFetchedMessage;
	}
	
}
