package org.adorsys.plh.pkix.core.cmp;

import java.util.concurrent.Executor;

import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Asynchronous reception of messages from the in memory server
 * 
 * @author francis
 *
 */
public class AsynchCMPMessageEndpoint implements CMPMessageEndpoint {
	private final Executor executor;
	private final CMPMessageEndpoint delegate;
	

	public AsynchCMPMessageEndpoint(Executor executor,
			CMPMessageEndpoint delegate) {
		this.executor = executor;
		this.delegate = delegate;
	}


	@Override
	public void receive(final PKIMessage message) {
		executor.execute(new Runnable() {
			@Override
			public void run() {
				delegate.receive(message);
			}
		});
	}
}
