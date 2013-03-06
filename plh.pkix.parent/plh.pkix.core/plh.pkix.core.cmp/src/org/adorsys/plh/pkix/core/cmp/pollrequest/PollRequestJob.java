package org.adorsys.plh.pkix.core.cmp.pollrequest;

import java.util.Collection;

import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestHandle;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * @author francis
 *
 */
public class PollRequestJob implements Runnable {

	private ActionContext actionContext;

	BuilderChecker checker = new BuilderChecker(PollRequestJob.class);
	@Override
	public void run() {
		PendingRequests pendingRequests = actionContext.get(PendingRequests.class);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
		checker.checkDirty().checkNull(pendingRequests, keyStoreWraper);
		Collection<PendingRequestHandle> handles = pendingRequests.listHandles();
		for (PendingRequestHandle pendingRequestHandle : handles) {
			if(pendingRequestHandle.getDisposed()!=null) continue;
			PendingRequestData pendingRequestData = pendingRequests.loadPendingRequest(pendingRequestHandle.getCertReqId());
			ActionContext localContext = new ActionContext(actionContext);
			localContext.put(PendingRequestData.class, null, pendingRequestData);
			
			new PollRequestBuilder().build(localContext);
			pendingRequestData = localContext.get(PendingRequestData.class);
			PendingRequest pendingPollRequest = pendingRequestData.getPendingRequest();
			PKIMessage pendingPollRequestMessage = pendingPollRequest.getPkiMessage();
			CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
			try {
				cmpMessenger.send(pendingPollRequestMessage);
				// set announced
				pendingRequests.disposePendingRequest(pendingPollRequest.getCertReqId().getPositiveValue());
			} catch(Exception ex){
				// TODO log message for bacth processing.// might be in the cert ann object
			}
		}
	}
}
