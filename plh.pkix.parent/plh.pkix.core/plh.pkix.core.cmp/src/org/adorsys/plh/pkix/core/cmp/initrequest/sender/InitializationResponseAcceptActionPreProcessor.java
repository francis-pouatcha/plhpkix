package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.CertAndCertPath;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Prepares and invoke the {@link InitializationResponseAcceptActionExecutor}. Forwards control
 * to the {@link ActionHandler} in the context in case of error.
 * @author francis
 *
 */
public class InitializationResponseAcceptActionPreProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseAcceptActionPreProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		ActionHandler actionHandler = actionContext.get1(ActionHandler.class,null);
		OutgoingRequests requests = actionContext.get1(OutgoingRequests.class);
		PKIMessage responseMessage = actionContext.get1(PKIMessage.class);
		checker.checkNull(responseMessage,requests);

		// store the incoming response
		CMPRequest cmpRequest = requests.loadRequest(responseMessage.getHeader().getTransactionID());
		
		checker.checkNull(actionHandler);
		try {
			List<ProcessingResults<CertAndCertPath>> processingResultList = new InitializationResponseAcceptActionExecutor()
					.withActionContext(actionContext)
					.execute();
			List<Action> actions = new ArrayList<Action>();
			for (ProcessingResults<CertAndCertPath> processingResults : processingResultList) {
				Action postAction = new InitializationResponseAcceptPostAction(actionContext, processingResults);
				actions.add(postAction);
			}
			actionHandler.handle(actions);
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		}
	}
}
