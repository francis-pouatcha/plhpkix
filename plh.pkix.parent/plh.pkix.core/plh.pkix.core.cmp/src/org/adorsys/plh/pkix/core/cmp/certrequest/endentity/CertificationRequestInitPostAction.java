package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;

public class CertificationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";

	private ProcessingResults<OutgoingCertificationRequestData> processingResults;
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitPostAction.class);
	public CertificationRequestInitPostAction(
			ActionContext actionContext,
			ProcessingResults<OutgoingCertificationRequestData> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		this.processingResults = processingResults;
		// best case
		addProcessor(SEND_OUTCOME, CertificationRequestSendActionProcessor.class);
		// error, park request for user feedback.
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		this.processingResults = processingResults;
		
		if(processingResults.hasError()){
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		} else if(processingResults.hasReturnValue()){
			setOutcome(SEND_OUTCOME);
		} else {
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		}
	}
	public ProcessingResults<OutgoingCertificationRequestData> getProcessingResults() {
		return processingResults;
	}
}
