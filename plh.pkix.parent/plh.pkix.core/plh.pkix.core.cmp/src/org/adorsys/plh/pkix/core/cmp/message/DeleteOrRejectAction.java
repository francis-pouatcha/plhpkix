package org.adorsys.plh.pkix.core.cmp.message;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;

public class DeleteOrRejectAction extends GenericAction {
	
	public DeleteOrRejectAction(ActionContext actionContext) {
		super(actionContext);
		addProcessor(DELETE_OUTCOME, DeleteMessageActionProcessor.class);
		addProcessor(REJECT_OUTCOME, RejectMessageActionProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
	}
}
