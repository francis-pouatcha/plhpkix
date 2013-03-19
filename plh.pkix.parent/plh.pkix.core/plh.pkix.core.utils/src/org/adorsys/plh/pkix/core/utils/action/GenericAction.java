package org.adorsys.plh.pkix.core.utils.action;


public class GenericAction extends AbstractAction {
	private String outcome;

	public GenericAction(ActionContext actionContext) {
		super(actionContext);
	}
	
	public void setOutcome(String outcome) {
		this.outcome = outcome;
	}

	@Override
	public String getOutcome() {
		return outcome;
	}
}
