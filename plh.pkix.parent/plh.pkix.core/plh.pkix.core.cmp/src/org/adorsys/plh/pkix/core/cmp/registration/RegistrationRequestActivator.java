package org.adorsys.plh.pkix.core.cmp.registration;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class RegistrationRequestActivator extends ModuleActivator {

	public RegistrationRequestActivator(ActionContext accountContext,
			FileWrapper accountDir) {
		super(accountContext, accountDir);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(RegistrationRequestInitActionProcessor.class, new RegistrationRequestInitActionProcessor());
		actionContext.put(RegistrationRequestSendActionProcessor.class, new RegistrationRequestSendActionProcessor());		
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return null;
	}

	@Override
	public Integer getIncomingMessageType() {
		return null;
	}
}
