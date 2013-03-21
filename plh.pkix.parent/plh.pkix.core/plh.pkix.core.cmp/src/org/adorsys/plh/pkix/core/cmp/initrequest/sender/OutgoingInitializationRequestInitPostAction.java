package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageActionProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;

public class OutgoingInitializationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";
	
	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationRequestInitPostAction.class);
	public OutgoingInitializationRequestInitPostAction(
			ActionContext actionContext,
			ProcessingResults<CMPRequest> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);

		// best case
		addProcessor(SEND_OUTCOME, OutgoingInitializationRequestSendActionProcessor.class);
		// error, park request for user feedback.
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_OUTCOME, DeleteMessageActionProcessor.class);
		
		if(processingResults.hasError()){
			setOutcome(DELETE_OUTCOME);
		} else if(processingResults.hasReturnValue()){
			actionContext.put(CMPRequest.class, processingResults.getReturnValue());
			setOutcome(SEND_OUTCOME);
		} else {
			setOutcome(DELETE_OUTCOME);
		}
	}
}
