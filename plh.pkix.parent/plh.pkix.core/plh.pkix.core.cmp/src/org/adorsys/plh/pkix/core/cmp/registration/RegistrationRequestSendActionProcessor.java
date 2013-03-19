package org.adorsys.plh.pkix.core.cmp.registration;

import java.util.Date;
import java.util.concurrent.Executor;

import org.adorsys.plh.pkix.core.cmp.CMPMessageEndpoint;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class RegistrationRequestSendActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestSendActionProcessor.class);
	
	@Override
	public void process(ActionContext actionContext) {
		final CMPMessenger cmpMessenger = actionContext.get1(CMPMessenger.class);
		final CMPMessageEndpoint cmpMessageEndpoint = actionContext.get1(CMPMessageEndpoint.class);
		final CMPRequests requests = actionContext.get1(CMPRequests.class);
		checker.checkNull(cmpMessenger, requests);
		final CMPRequest request = actionContext.get1(CMPRequest.class);
		checker.checkNull(request);
		// TODO store send request before detach thread.
		Executor executor = actionContext.get1(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME);
		checker.checkNull(executor);
		executor.execute(new Runnable() {	
			@Override
			public void run() {
				PKIMessage registrationRequestMessage = request.getPkiMessage();
				DERGeneralizedTime now = new DERGeneralizedTime(new Date());
				try {
					cmpMessenger.registerMessageEndPoint(cmpMessageEndpoint,registrationRequestMessage);
					request.addStatus(ASN1ProcessingStatus.request_sent);
					request.setDisposed(now);
					request.disposeCurentAction();
					requests.storeRequest(request);
				} catch(PlhUncheckedException e){
					ErrorMessageHelper.processError(request, requests, e.getErrorMessage());
				} catch (RuntimeException r){
					ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r, RegistrationRequestSendActionProcessor.class.getName()+"#process");
					ErrorMessageHelper.processError(request, requests, errorMessage);
				}
			}
		});
	}
	
}
