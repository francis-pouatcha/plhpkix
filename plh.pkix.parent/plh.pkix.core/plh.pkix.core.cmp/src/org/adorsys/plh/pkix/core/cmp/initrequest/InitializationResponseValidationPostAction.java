package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.ProcessMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.RejectMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class InitializationResponseValidationPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseValidationPostAction.class);
	public InitializationResponseValidationPostAction(
			ActionContext actionContext,
			CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		
		addProcessor(ACCEPT_OUTCOME, InitializationResponseAcceptActionPreProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		addProcessor(PROCESS_AFTER_CONFIRM_OUTCOME, ProcessMessageAfterConfirmActionPreProcessor.class);
		this.processingResults = processingResults;
		
		if(processingResults.hasError()){
			List<ErrorBundle> errors = processingResults.getErrors();
			boolean conformityError = false;
//			boolean containsResponseError = false;
			boolean containsCertificateError = false;
			for (ErrorBundle errorBundle : errors) {
				if(errorBundle.getId().contains(".conformity.")){
					conformityError = true;
				} else if(errorBundle.getId().contains(".certificate.")){
					containsCertificateError = true;
				}
			}
			if(conformityError){
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
			} else if(containsCertificateError){
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			} else{
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
			}
		} else if(processingResults.hasReturnValue()){
			setOutcome(ACCEPT_OUTCOME);
		} else {
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		}
	}
	public CertificateValidatingProcessingResult<ProtectedPKIMessage> getProcessingResults() {
		return processingResults;
	}
}
