package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.message.CertificateChainActionData;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;

/**
 * Display the data to the user and let the user enter the serial number of the top
 * most certificate of the chain to confirm import.
 * @author francis
 *
 */
public class InitializationResponseImportActionPreProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportActionPreProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		CertificateChainActionData actionData = actionContext.get(CertificateChainActionData.class,null);
		
		checker.checkNull(actionData);
		
		// Import the certificate into key store
		CertificateChain certificateChain = actionData.getCertificateChain();
		
		ActionHandler actionHandler = actionContext.get(ActionHandler.class,null);
		checker.checkNull(actionHandler, certificateChain);

		InitializationResponseImportPreAction preAction = new InitializationResponseImportPreAction(actionContext, certificateChain);
		List<Action> actions = new ArrayList<Action>();
		actions.add(preAction);
		actionHandler.handle(actions);
	}
}
