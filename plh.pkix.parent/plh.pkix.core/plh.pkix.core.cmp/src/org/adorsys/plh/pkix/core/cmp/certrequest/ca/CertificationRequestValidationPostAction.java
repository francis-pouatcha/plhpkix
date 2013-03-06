package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

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

public class CertificationRequestValidationPostAction extends GenericAction {
	public static final String APPROVAL_OUTCOME="approval";

	private CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults;
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestValidationPostAction.class);
	public CertificationRequestValidationPostAction(
			ActionContext actionContext,
			CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		
		addProcessor(APPROVAL_OUTCOME, CertificationRequestApprovalActionProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		addProcessor(PROCESS_AFTER_CONFIRM_OUTCOME, ProcessMessageAfterConfirmActionPreProcessor.class);
		this.processingResults = processingResults;
		
		if(processingResults.hasError()){
			List<ErrorBundle> errors = processingResults.getErrors();
			boolean containsPendingMessageError = false;
			boolean containsResponseError = false;
			boolean containsCertificateError = false;
			for (ErrorBundle errorBundle : errors) {
				if(errorBundle.getId().contains(".request.")){
					containsPendingMessageError = true;
				} else if(errorBundle.getId().contains(".response.")){
					containsResponseError = true;
				} else if(errorBundle.getId().contains(".certificate.")){
					containsCertificateError = true;
				}
			}
			if(containsPendingMessageError){
				// create a delete after confirm action and give to the handler.
				setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
			} else if(containsResponseError){
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
			} else if(containsCertificateError){
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			} else{
				// create a delete after confirm action and give to the handler.
				setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
			}
		} else if(processingResults.hasReturnValue()){
			setOutcome(APPROVAL_OUTCOME);
		} else {
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		}
	}
	public CertificateValidatingProcessingResult<ProtectedPKIMessage> getProcessingResults() {
		return processingResults;
	}
}
