package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class CertificationRequestValidationProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationRequestValidationProcessor.class);
	public void process(ActionContext actionContext) {
		
		checker.checkDirty().checkNull(actionContext);

		PKIMessageActionData messageActionData = actionContext.get(PKIMessageActionData.class,null);		
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		ActionHandler actionHandler = actionContext.get(ActionHandler.class,null);
		checker.checkNull(keyStoreWraper,messageActionData,actionHandler);

		CertificateValidatingProcessingResult<ProtectedPKIMessage> 
		processingResults = new PkiMessageChecker()
			.withKeyStoreWraper(keyStoreWraper)
			.check(messageActionData.getPkiMessage());
		
		CertificationRequestValidationPostAction postAction = new CertificationRequestValidationPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}
}
