package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.util.Date;
import java.util.concurrent.Executor;

import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class OutgoingInitializationResponseSendActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationResponseSendActionProcessor.class);
	
	@Override
	public void process(ActionContext actionContext) {
		final CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
		checker.checkNull(cmpMessenger);
		
		final IncomingInitializationRequestData requestData = actionContext.get(IncomingInitializationRequestData.class);		
		Executor executor = actionContext.get(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME);
		checker.checkNull(requestData);
		checker.checkNull(executor);
		final IncomingInitializationRequests initializationRequests = actionContext.get(IncomingInitializationRequests.class);
		
		executor.execute(new Runnable() {	
			@Override
			public void run() {
				IncomingRequest incomingRequest = requestData.getIncomingRequest();
				PKIMessage responseMessage = incomingRequest.getResponseMessage();
				DERGeneralizedTime now = new DERGeneralizedTime(new Date());
				try {
					cmpMessenger.send(responseMessage);
					incomingRequest.setLastReply(now);
					incomingRequest.setStatus(new DERIA5String(OutgoingRequest.STATUS_OK));
					initializationRequests.storeRequest(incomingRequest.getCertReqId().getPositiveValue(), requestData);
				} catch(Exception e){
					incomingRequest.setLastReply(now);
					incomingRequest.setStatus(new DERIA5String(OutgoingRequest.STATUS_ERROR + e.getMessage()));
					initializationRequests.storeRequest(incomingRequest.getCertReqId().getPositiveValue(), requestData);
				}
			}
		});
	}
}
