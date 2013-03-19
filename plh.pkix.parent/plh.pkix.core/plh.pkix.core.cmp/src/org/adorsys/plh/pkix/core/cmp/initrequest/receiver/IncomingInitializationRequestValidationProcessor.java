package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class IncomingInitializationRequestValidationProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(IncomingInitializationRequestValidationProcessor.class);
	public void process(ActionContext actionContext) {
		
		checker.checkNull(actionContext);

		PKIMessageActionData messageActionData = actionContext.get(PKIMessageActionData.class);		
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
		ActionHandler actionHandler = actionContext.get(ActionHandler.class);
		IncomingInitializationRequests initializationRequests = actionContext.get(IncomingInitializationRequests.class);
		checker.checkNull(keyStoreWraper,messageActionData,actionHandler);
		
		// store the incoming message
		PKIMessage pkiMessage = messageActionData.getPkiMessage();
		IncomingRequest incomingRequest = new IncomingRequest(pkiMessage, new DERGeneralizedTime(new Date()));
		IncomingInitializationRequestData requestData = new IncomingInitializationRequestData(incomingRequest);
		actionContext.put(IncomingInitializationRequestData.class, requestData);
		initializationRequests.storeRequest(requestData);

		CertificateValidatingProcessingResult<ProtectedPKIMessage> 
		processingResults = new PkiMessageChecker()
			.withKeyStoreWraper(keyStoreWraper)
			.check(messageActionData.getPkiMessage());
		
		IncomingInitializationRequestValidationPostAction postAction = new IncomingInitializationRequestValidationPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}
}
