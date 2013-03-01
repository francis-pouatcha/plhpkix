package org.adorsys.plh.pkix.core.cmp.initrequest;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.RejectMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;

public class InitializationResponseImportPreAction extends GenericAction {
	public static final String IMPORT_OUTCOME="import";

	private CertificateChain certificateChain;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportPreAction.class);
	public InitializationResponseImportPreAction(
			ActionContext actionContext,
			CertificateChain certificateChain) {
		super(actionContext);
		checker.checkNull(actionContext,certificateChain);
		addProcessor(IMPORT_OUTCOME, InitializationResponseImportActionProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		this.certificateChain = certificateChain;
	}
	public CertificateChain getCertificateChain() {
		return certificateChain;
	}
}
