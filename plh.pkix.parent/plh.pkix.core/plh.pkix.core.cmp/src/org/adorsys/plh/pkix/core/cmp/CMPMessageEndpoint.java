package org.adorsys.plh.pkix.core.cmp;

import org.bouncycastle.asn1.cmp.PKIMessage;

public interface CMPMessageEndpoint {

	/**
	 * Receives from the server the next pki message addressed 
	 * to this end entity.
	 * 
	 * @return
	 */
	public void receive(PKIMessage message);
}
