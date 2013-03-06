package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.cmp.PKIBody;

public class OutgoingInitializationRequestActivator extends ModuleActivator {

	InitializationResponseValidationActionProcessor incomingProcessor = new InitializationResponseValidationActionProcessor();
	public OutgoingInitializationRequestActivator(ActionContext accountContext,
			FileWrapper accountDir) {
		super(accountContext, accountDir);
	}

	@Override
	protected void activate(ActionContext actionContext, FileWrapper accountDir) {
		actionContext.put(OutgoingInitializationRequests.class, new OutgoingInitializationRequests(accountDir));
		actionContext.put(OutgoingInitializationRequestInitActionProcessor.class, new OutgoingInitializationRequestInitActionProcessor());
		actionContext.put(OutgoingInitializationRequestSendActionProcessor.class, new OutgoingInitializationRequestSendActionProcessor());		

		actionContext.put(InitializationResponseAcceptActionPreProcessor.class, new InitializationResponseAcceptActionPreProcessor());		
		actionContext.put(InitializationResponseImportActionPreProcessor.class, new InitializationResponseImportActionPreProcessor());		
		actionContext.put(InitializationResponseImportActionProcessor.class, new InitializationResponseImportActionProcessor());		
	}

	@Override
	public ActionProcessor getIncommingProcessorClass() {
		return incomingProcessor;		
	}

	@Override
	public Integer getIncomingMessageType() {
		return PKIBody.TYPE_INIT_REP;
	}
}
