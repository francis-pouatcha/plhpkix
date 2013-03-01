package org.adorsys.plh.pkix.core.utils.action;

import java.util.HashMap;
import java.util.Map;

public abstract class AbstractAction implements Action {

	private ActionContext actionContext;
	private Map<String, Class<? extends ActionProcessor>> actionProcessors = new HashMap<String, Class<? extends ActionProcessor>>();
	
	public AbstractAction(ActionContext actionContext) {
		this.actionContext = actionContext;
	}

	public ActionContext getActionContext() {
		return actionContext;
	}

	@Override
	public Class<? extends ActionProcessor> getActionProcessor(String outCome) {
		return actionProcessors.get(outCome);
	}

	public void addProcessor(String outcome, Class<? extends ActionProcessor> processor){
		actionProcessors.put(outcome, processor);
	}
}
