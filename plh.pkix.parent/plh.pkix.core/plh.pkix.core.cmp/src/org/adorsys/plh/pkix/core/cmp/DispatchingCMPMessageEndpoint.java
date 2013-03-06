package org.adorsys.plh.pkix.core.cmp;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Receives a cmp message on behalves of it's owner, read the message type
 * and forward processing to the corresponding processor.
 * @author francis
 *
 */
public class DispatchingCMPMessageEndpoint implements CMPMessageEndpoint {
	
	private final ModuleActivators moduleActivators;
	private final ActionContext accountContext;
	public DispatchingCMPMessageEndpoint(ModuleActivators moduleActivators,ActionContext accountContext) {
		this.moduleActivators = moduleActivators;
		this.accountContext = accountContext;
	}

	@Override
	public void receive(PKIMessage message) {
		PKIBody pkiBody = message.getBody();
		Integer type = pkiBody.getType();
		ModuleActivator moduleActivator = moduleActivators.getModuleActivator(type);
		if(moduleActivator==null)
			return;// ignore message
		moduleActivator.getIncommingProcessorClass().process(accountContext);
	}
}
