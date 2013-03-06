package org.adorsys.plh.pkix.core.cmp;

import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * A interface used by cmp end entities to send and receive cmp messages.
 * 
 * @author francis
 *
 */
public interface CMPMessenger {

	/**
	 * Send a pki message to the messaging server
	 * 
	 * @param pkiMessage
	 * @return
	 */
	public void send(PKIMessage pkiMessage);

	/**
	 * Registers a message endpoint, sending an initialization request with the
	 * endpoint's certificate to the server. Endpoint will not be accepted
	 * if there is any existing endpoint with the same public key id.
	 * @param endpoint
	 * @param initRequest
	 * @return
	 */
	public void registerMessageEndPoint(CMPMessageEndpoint endpoint, PKIMessage initRequest);
}
