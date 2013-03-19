package org.adorsys.plh.pkix.core.utils.action;

import java.util.List;

public class SimpleActionHandler implements ActionHandler {
	
	@Override
	public void handle(List<Action> actions) {
		for (Action action : actions) {
			String outcome = action.getOutcome();
			Class<? extends ActionProcessor> actionProcessorClass = action.getActionProcessor(outcome);
			ActionContext actionContext = action.getActionContext();
			ActionProcessor actionProcessor = actionContext.get1(actionProcessorClass, null);
			actionProcessor.process(actionContext);
		}
	}
}
