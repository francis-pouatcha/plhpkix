package org.adorys.plh.pkix.core.cmp.stores;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;

public class FetchRequestHolder {

	private static final Map<X500Name, FetchRequestHolder> instances = new HashMap<X500Name, FetchRequestHolder>();

	private PKIMessage lastFetchedMessage;
	
	public static FetchRequestHolder getInstance(X500Name role){
		FetchRequestHolder fetchRequestHolder = instances.get(role);
		if(fetchRequestHolder!=null) return fetchRequestHolder;

		fetchRequestHolder = new FetchRequestHolder();
		instances.put(role, fetchRequestHolder);
		return fetchRequestHolder;
	}

	public PKIMessage getLastFetchedMessage() {
		return lastFetchedMessage;
	}

	public void setLastFetchedMessage(PKIMessage lastFetchedMessage) {
		this.lastFetchedMessage = lastFetchedMessage;
	}
	
}
