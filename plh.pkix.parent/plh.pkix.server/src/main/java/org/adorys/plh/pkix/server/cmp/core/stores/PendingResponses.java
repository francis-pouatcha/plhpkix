package org.adorys.plh.pkix.server.cmp.core.stores;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;

public class PendingResponses {

	private static final Map<X500Name, PendingResponses> instances = new HashMap<X500Name, PendingResponses>();

	public static PendingResponses getInstance(X500Name role){
		PendingResponses pendingResponses = instances.get(role);
		if(pendingResponses!=null) return pendingResponses;

		pendingResponses = new PendingResponses();
		instances.put(role, pendingResponses);
		return pendingResponses;
	}

	
	private LinkedList<PKIMessage> pkiMessages = new LinkedList<PKIMessage>();
	
	public PKIMessage getNext(){
		return pkiMessages.poll();
	}
	
	public void add(PKIMessage certificateHolder){
		pkiMessages.add(certificateHolder);
	}
}
