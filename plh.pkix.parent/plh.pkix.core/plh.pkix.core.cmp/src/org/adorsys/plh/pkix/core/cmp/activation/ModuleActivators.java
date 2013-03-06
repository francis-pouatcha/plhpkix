package org.adorsys.plh.pkix.core.cmp.activation;

import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.cmp.initrequest.receiver.IncomingInitializationRequestActivator;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.OutgoingInitializationRequestActivator;
import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestActivator;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class ModuleActivators {

	private Map<Integer, ModuleActivator> modules = new HashMap<Integer, ModuleActivator>();

	public ModuleActivators(ActionContext accountContext, FileWrapper accountDir) {
		RegistrationRequestActivator registrationRequestActivator = new RegistrationRequestActivator(accountContext, accountDir);
		if(registrationRequestActivator.getIncomingMessageType()!=null)
			modules.put(registrationRequestActivator.getIncomingMessageType(), registrationRequestActivator);
		IncomingInitializationRequestActivator incomingInitializationRequestActivator = new IncomingInitializationRequestActivator(accountContext, accountDir);
		if(incomingInitializationRequestActivator.getIncomingMessageType()!=null)
			modules.put(incomingInitializationRequestActivator.getIncomingMessageType(), incomingInitializationRequestActivator);
		OutgoingInitializationRequestActivator outgoingInitializationRequestActivator = new OutgoingInitializationRequestActivator(accountContext, accountDir);
		if(outgoingInitializationRequestActivator.getIncomingMessageType()!=null)
			modules.put(outgoingInitializationRequestActivator.getIncomingMessageType(), outgoingInitializationRequestActivator);
	}
	
	public ModuleActivator getModuleActivator(Integer messageType){
		return modules.get(messageType);
	}
}
