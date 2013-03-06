package org.adorsys.plh.pkix.core.cmp.registration;

import java.util.Date;
import java.util.concurrent.Executor;

import org.adorsys.plh.pkix.core.cmp.CMPMessageEndpoint;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class RegistrationRequestSendActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestSendActionProcessor.class);
	
	// @Asynch
	@Override
	public void process(ActionContext actionContext) {
		final CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
		final CMPMessageEndpoint cmpMessageEndpoint = actionContext.get(CMPMessageEndpoint.class);
		final OutgoingRegistrationRequests registrationRequests = actionContext.get(OutgoingRegistrationRequests.class);
		checker.checkNull(cmpMessenger, registrationRequests);
		final OutgoingRegistrationRequestData registrationRequestData = actionContext.get(OutgoingRegistrationRequestData.class);
		checker.checkNull(registrationRequestData);
		
		Executor executor = actionContext.get(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME);
		checker.checkNull(executor);
		executor.execute(new Runnable() {	
			@Override
			public void run() {
				OutgoingRequest registrationRequest = registrationRequestData.getOutgoingRequest();
				PKIMessage registrationRequestMessage = registrationRequest.getPkiMessage();
				DERGeneralizedTime now = new DERGeneralizedTime(new Date());
				try {
					cmpMessenger.registerMessageEndPoint(cmpMessageEndpoint,registrationRequestMessage);
					registrationRequest.setSent(now);
					registrationRequest.setDisposed(now);
					registrationRequest.setStatus(new DERIA5String(OutgoingRequest.STATUS_OK));
					registrationRequests.storeRegistrationRequest(registrationRequest.getCertReqId().getPositiveValue(), registrationRequestData);
				} catch(Exception e){
					registrationRequest.setSent(now);
					registrationRequest.setStatus(new DERIA5String(OutgoingRequest.STATUS_ERROR + e.getMessage()));
					registrationRequests.storeRegistrationRequest(registrationRequest.getCertReqId().getPositiveValue(), registrationRequestData);
				}
			}
		});
	}
}
