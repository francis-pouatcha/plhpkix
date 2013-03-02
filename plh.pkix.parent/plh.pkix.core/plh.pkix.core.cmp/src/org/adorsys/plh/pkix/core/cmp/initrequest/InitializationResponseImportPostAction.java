package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageActionProcessor;
import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.RejectMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;

public class InitializationResponseImportPostAction extends GenericAction {
	private ProcessingResults<List<X509CertificateHolder>> processingResults;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportPostAction.class);
	public InitializationResponseImportPostAction(
			ActionContext actionContext,
			ProcessingResults<List<X509CertificateHolder>> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		addProcessor(DELETE_OUTCOME, DeleteMessageActionProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		this.processingResults = processingResults;
		
		if(processingResults.hasError()){
			List<ErrorBundle> errors = processingResults.getErrors();
			boolean containsPendingMessageError = false;
			boolean containsResponseError = false;
			for (ErrorBundle errorBundle : errors) {
				if(errorBundle.getId().contains(".request.")){
					containsPendingMessageError = true;
				} else if(errorBundle.getId().contains(".response.")){
					containsResponseError = true;
				}
			}
			if(containsPendingMessageError){
				// create a delete after confirm action and give to the handler.
				setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
			} else if(containsResponseError){
				// if the pending message had sent back an error already, confirm and delete message
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
				// creates a delete or send back message and give to the handler.
			} else{
				// create a delete after confirm action and give to the handler.
				setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
			}
		} else if(processingResults.hasReturnValue()){
			setOutcome(DELETE_OUTCOME);// sucess, delete process
		} else {
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		}
	}
	public ProcessingResults<List<X509CertificateHolder>> getProcessingResults() {
		return processingResults;
	}
}
