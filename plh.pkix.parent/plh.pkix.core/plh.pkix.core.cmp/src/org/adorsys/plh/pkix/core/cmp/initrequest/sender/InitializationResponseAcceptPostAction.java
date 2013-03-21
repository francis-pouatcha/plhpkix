package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.message.ProcessMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.CertAndCertPath;

public class InitializationResponseAcceptPostAction extends GenericAction {
	public static final String IMPORT_ON_CONFIRM_OUTCOME="import_on_confir";

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseAcceptPostAction.class);
	public InitializationResponseAcceptPostAction(
			ActionContext actionContext,
			ProcessingResults<CertAndCertPath> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		addProcessor(IMPORT_ON_CONFIRM_OUTCOME, InitializationResponseImportActionPreProcessor.class);
		addProcessor(PROCESS_AFTER_CONFIRM_OUTCOME, ProcessMessageAfterConfirmActionPreProcessor.class);
		
		if(processingResults.hasError()){
			setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
		} else {
			setOutcome(IMPORT_ON_CONFIRM_OUTCOME);
		}
	}
}
