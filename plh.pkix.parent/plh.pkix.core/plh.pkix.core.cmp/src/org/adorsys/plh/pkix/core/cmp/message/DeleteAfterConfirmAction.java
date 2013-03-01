package org.adorsys.plh.pkix.core.cmp.message;

import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;

/**
 * When the confirm dialog is displayed to the user, if the user clicks ok, 
 * this is considered a success. The the message is deleted. If the user
 * click cancel, the message is left in the storage.
 * 
 * @author francis
 *
 */
public class DeleteAfterConfirmAction extends GenericAction {
	public DeleteAfterConfirmAction(ActionContext actionContext) {
		super(actionContext);
		addProcessor(Action.OK_OUTCOME, DeleteMessageActionProcessor.class);
		addProcessor(Action.CANCEL_OUTCOME, NullActionProcessor.class);
	}
}
