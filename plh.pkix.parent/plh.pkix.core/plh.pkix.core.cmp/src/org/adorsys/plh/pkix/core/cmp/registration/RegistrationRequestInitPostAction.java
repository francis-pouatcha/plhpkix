package org.adorsys.plh.pkix.core.cmp.registration;

import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;

public class RegistrationRequestInitPostAction extends GenericAction {
	public static final String SEND_OUTCOME="send";

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestInitPostAction.class);
	
	private OutgoingRequests registrationRequests;
	public RegistrationRequestInitPostAction(ActionContext actionContext) {
		super(actionContext);
		checker.checkNull(actionContext);
		registrationRequests = actionContext.get1(OutgoingRequests.class);
		checker.checkNull(registrationRequests);

		// best case
		addProcessor(SEND_OUTCOME, RegistrationRequestSendActionProcessor.class);
		// error, park request for user feedback.
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_AFTER_CONFIRM_OUTCOME, DeleteMessageAfterConfirmActionPreProcessor.class);

		CMPRequest outgoingRequest = actionContext.get1(CMPRequest.class);
		if(outgoingRequest==null || (outgoingRequest!=null && outgoingRequest.hasError())){
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		} else {
			setOutcome(SEND_OUTCOME);
		}
	}
}
