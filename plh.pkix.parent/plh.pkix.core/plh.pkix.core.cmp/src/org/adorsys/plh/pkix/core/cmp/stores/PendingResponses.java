package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.LinkedList;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class PendingResponses {

	private LinkedList<PKIMessage> pkiMessages = new LinkedList<PKIMessage>();	
	public PKIMessage getNext(){
		return pkiMessages.poll();
	}
	
	public void add(PKIMessage certificateHolder){
		pkiMessages.add(certificateHolder);
	}
}
