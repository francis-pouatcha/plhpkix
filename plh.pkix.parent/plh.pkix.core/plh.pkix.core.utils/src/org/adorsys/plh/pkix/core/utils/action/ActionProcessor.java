package org.adorsys.plh.pkix.core.utils.action;

/**
 * Process the feedback using data stored in the feedback context and 
 * stores results in the feedback context.
 * 
 * @author francis
 *
 */
public interface ActionProcessor {

	public void process(ActionContext context);
}
