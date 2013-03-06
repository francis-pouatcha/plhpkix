package org.adorsys.plh.pkix.core.cmp.registration;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;

/**
 * Builds a registration request
 * 
 * @author francis
 *
 */
public class RegsitrationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(RegsitrationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		// The private key entry to be registered.
		PrivateKeyEntry privateKeyEntry = context.get(PrivateKeyEntry.class);
		OutgoingRegistrationRequests outgoingRegistrationRequests = context.get(OutgoingRegistrationRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		
		checker.checkNull(privateKeyEntry,outgoingRegistrationRequests,actionHandler);
		
		ProcessingResults<OutgoingRegistrationRequestData> processingResults = new RegistrationRequestInitActionExecutor()
			.build(privateKeyEntry);

		OutgoingRegistrationRequestData certificationRequestData = processingResults.getReturnValue();
		OutgoingRequest certificationRequest = certificationRequestData.getOutgoingRequest();
		outgoingRegistrationRequests.storeRegistrationRequest(certificationRequest.getCertReqId().getPositiveValue(), certificationRequestData);
		Action postAction = new RegistrationRequestInitPostAction(context, processingResults);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
