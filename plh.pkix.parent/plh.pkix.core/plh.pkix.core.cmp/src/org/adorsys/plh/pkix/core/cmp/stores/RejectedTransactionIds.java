package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;

/**
 * Collect the list of rejected transaction id in memory and simply 
 * delete non conforming message coming in with any of these tracked
 * transaction id.
 * 
 * @author francis
 *
 */
public class RejectedTransactionIds {

	private Set<ASN1OctetString> txids = new HashSet<ASN1OctetString>();
	
	public void addTransactionId(ASN1OctetString txid){
		if(txids.size()>100000)txids = new HashSet<ASN1OctetString>();
		txids.add(txid);
	}
	
	public boolean hasTransactionId(ASN1OctetString txid){
		return txids.contains(txid);
	}
}
