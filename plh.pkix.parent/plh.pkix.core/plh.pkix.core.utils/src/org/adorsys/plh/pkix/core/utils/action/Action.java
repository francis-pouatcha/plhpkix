package org.adorsys.plh.pkix.core.utils.action;



public interface Action {
	
	public static final String ERROR_OUTCOME = "errors";
	public static final String NOTIFICATION_OUTCOME = "notifications";
	public static final String SUCCESS_OUTCOME = "success";
	public static final String OK_OUTCOME = "ok";
	public static final String CANCEL_OUTCOME = "cancel";
	public static final String REJECT_OUTCOME = "reject";
	public static final String DELETE_OUTCOME = "delete";
	public static final String USER_FEEDBACK_OUTCOME = "userFedback";
	
	public Class<? extends ActionProcessor> getActionProcessor(String outCome);

	public ActionContext getActionContext();	
	
	public String getOutcome();
}
