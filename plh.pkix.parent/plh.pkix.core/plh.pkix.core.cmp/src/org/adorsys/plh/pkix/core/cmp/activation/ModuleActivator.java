package org.adorsys.plh.pkix.core.cmp.activation;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public abstract class ModuleActivator {

	public ModuleActivator(ActionContext accountContext, FileWrapper accountDir) {
		activate(accountContext, accountDir);
	}

	protected abstract void activate(ActionContext actionContext, FileWrapper accountDir);
	
	/**
	 * Returns the incoming message processor.
	 * 
	 * @return
	 */
	public abstract ActionProcessor getIncommingProcessorClass();
	
	public abstract Integer getIncomingMessageType();
}
