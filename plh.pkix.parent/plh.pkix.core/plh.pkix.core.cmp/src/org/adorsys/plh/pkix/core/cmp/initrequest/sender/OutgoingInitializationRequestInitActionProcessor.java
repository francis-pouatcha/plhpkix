package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

/**
 * Builds a registration request
 * 
 * @author francis
 *
 */
public class OutgoingInitializationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		OutgoingInitializationRequests initializationRequests = context.get(OutgoingInitializationRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		KeyStoreWraper keyStoreWraper = context.get(KeyStoreWraper.class);
		InitializationRequestFieldHolder f = context.get(InitializationRequestFieldHolder.class);
		
		checker.checkDirty().checkNull(keyStoreWraper,initializationRequests,actionHandler);
				
		OutgoingInitializationRequestInitActionExecutor builder = new OutgoingInitializationRequestInitActionExecutor()
				.withCertAuthorityName(f.getCertAuthorityName())
				.withNotAfter(f.getNotAfter())
				.withNotBefore(f.getNotBefore())
				.withReceiverCertificate(f.getReceiverCertificate())
				.withReceiverEmail(f.getReceiverEmail())
				.withSubjectAltNames(f.getSubjectAltNames())
				.withSubjectDN(f.getSubjectDN())
				.withSubjectPublicKeyInfo(f.getSubjectPublicKeyInfo());
		if(f.isCaSet())builder = builder.withCa(f.isCa());
		if(f.isKeyUsageSet())builder=builder.withKeyUsage(f.getKeyUsage());
		
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
		ProcessingResults<OutgoingInitializationRequestData> processingResults = builder.build(privateKeyEntry);

		OutgoingInitializationRequestData certificationRequestData = processingResults.getReturnValue();
		OutgoingRequest certificationRequest = certificationRequestData.getOutgoingRequest();
		initializationRequests.storeRequest(certificationRequest.getCertReqId().getPositiveValue(), certificationRequestData);
		Action postAction = new OutgoingInitializationRequestInitPostAction(context, processingResults);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
