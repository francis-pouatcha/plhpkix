package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Prepares and invoke the {@link InitializationResponseAcceptActionExecutor}. Forwards control
 * to the {@link ActionHandler} in the context in case of error. Proces
 * @author francis
 *
 */
public class InitializationResponseAcceptActionPreProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseAcceptActionPreProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		checker.checkNull(actionContext);
		
		ActionHandler actionHandler = actionContext.get(ActionHandler.class,null);
		
		checker.checkNull(actionHandler);

		ProcessingResults<List<X509CertificateHolder>> processingResults = 
				new InitializationResponseAcceptActionExecutor()
				.withActionContext(actionContext)
				.execute();

		InitializationResponseAcceptPostAction postAction = new InitializationResponseAcceptPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}
}
