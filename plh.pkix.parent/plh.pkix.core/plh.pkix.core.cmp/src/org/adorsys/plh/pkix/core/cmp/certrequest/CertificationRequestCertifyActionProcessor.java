package org.adorsys.plh.pkix.core.cmp.certrequest;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertTemplateActionData;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificationRequestCertifyActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(
			CertificationRequestValidationProcessor.class);

	@Override
	public void process(ActionContext feedbackContext) {
		// read dependency from context
		CertTemplateActionData certTemplateActionData = feedbackContext.get(
				CertTemplateActionData.class, null);
		KeyStoreWraper keyStoreWraper = feedbackContext.get(
				KeyStoreWraper.class, null);
		ActionHandler actionHandler = feedbackContext.get(ActionHandler.class,
				null);
		checker.checkNull(keyStoreWraper, certTemplateActionData, actionHandler);
		
		// invoke action executor
		ProcessingResults<List<X509CertificateHolder>> processingResults = new CertificationRequestCertifyActionExecutor()
				.withCertTemplate(certTemplateActionData.getCertTemplate()).execute(keyStoreWraper);
		CertificationRequestCertifyPostAction postAction = new CertificationRequestCertifyPostAction(
				feedbackContext, processingResults);
		
		// handle result
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}
}
