package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.RejectMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;

public class InitializationResponseImportPreAction extends GenericAction {
	public static final String IMPORT_OUTCOME="import";

	private ASN1CertificateChain certificateChain;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportPreAction.class);
	public InitializationResponseImportPreAction(
			ActionContext actionContext,
			ASN1CertificateChain certificateChain) {
		super(actionContext);
		checker.checkNull(actionContext,certificateChain);
		addProcessor(IMPORT_OUTCOME, InitializationResponseImportActionProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		this.certificateChain = certificateChain;
	}
	public ASN1CertificateChain getCertificateChain() {
		return certificateChain;
	}
}
