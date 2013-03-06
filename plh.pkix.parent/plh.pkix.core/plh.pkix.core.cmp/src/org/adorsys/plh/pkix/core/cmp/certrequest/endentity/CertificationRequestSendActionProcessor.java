package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.concurrent.Executor;

import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class CertificationRequestSendActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationRequestSendActionProcessor.class);
	
	// @Asynch
	@Override
	public void process(ActionContext actionContext) {
		checker.checkDirty();
		final CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
		final OutgoingCertificationRequests certificationRequests = actionContext.get(OutgoingCertificationRequests.class);
		checker.checkNull(cmpMessenger, certificationRequests);
		final OutgoingCertificationRequestData certificationRequestData = actionContext.get(OutgoingCertificationRequestData.class);
		checker.checkNull(certificationRequestData);
		
		Executor executor = actionContext.get(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME);
		executor.execute(new Runnable() {	
			@Override
			public void run() {
				OutgoingCertificationRequest certificationRequest = certificationRequestData.getOutgoingCertificationRequest();
				PKIMessage certificationRequestMessage = certificationRequest.getPkiMessage();
				String status = null;
				try {
					cmpMessenger.send(certificationRequestMessage);
					status="ok";
				} catch(Exception e){
					status = e.getMessage();
				}
				// set sent
				certificationRequests.markSent(certificationRequest.getCertReqId().getPositiveValue(), status);
			}
		});
	}
}
