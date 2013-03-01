package org.adorsys.plh.pkix.core.cmp.certrequest;

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

public class CertificationReplyValidationProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(
			CertificationReplyValidationProcessor.class);

	public void process(ActionContext actionContext) {
		checker.checkNull(actionContext);
		
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		ActionHandler actionHandler = actionContext.get(ActionHandler.class,null);
		PKIMessageActionData messageActionData = actionContext.get(PKIMessageActionData.class,null);
		checker.checkDirty().checkNull(
					messageActionData,
					keyStoreWraper,
					actionHandler);

		CertificateValidatingProcessingResult<ProtectedPKIMessage> 
					processingResults = new PkiMessageChecker()
						.withKeyStoreWraper(keyStoreWraper)
						.check(messageActionData.getPkiMessage());
		
		CertificationReplyValidationPostAction postAction = new CertificationReplyValidationPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}
}
