package org.adorsys.plh.pkix.core.utils.action;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.i18n.ErrorBundle;

public class ProcessingResults<T> implements ErrorsAndNotificationsHolder{

	private final List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
	private final List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();
	
	private T returnValue;
	private boolean returnValueSet = false;
	
	public ProcessingResults() {
		super();
	}

	public ProcessingResults(ProcessingResults<T> clone) {
		errors.addAll(clone.getErrors());
		notifications.addAll(clone.getNotifications());
		if(clone.hasReturnValue()){
			setReturnValue(clone.getReturnValue());
		}
	}

	public ProcessingResults(ErrorsAndNotificationsHolder clone) {
		errors.addAll(clone.getErrors());
		notifications.addAll(clone.getNotifications());
	}
	
	@Override
	public void addError(ErrorBundle errorBundle){
		errors.add(errorBundle);
	}

	@Override
	public void addNotification(ErrorBundle errorBundle){
		notifications.add(errorBundle);
	}

	@Override
	public List<ErrorBundle> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	@Override
	public List<ErrorBundle> getNotifications() {
		return Collections.unmodifiableList(notifications);
	}
	
	@Override
	public boolean hasError(){
		return !errors.isEmpty();
	}
	
	@Override
	public boolean hasNotification(){
		return !notifications.isEmpty();
	}
	
	@Override
	public void addErrors(List<ErrorBundle> in){
		errors.addAll(in);
	}

	@Override
	public void addNotifications(List<ErrorBundle> in){
		notifications.addAll(in);
	}

	public T getReturnValue() {
		return returnValue;
	}

	public void setReturnValue(T returnValue) {
		returnValueSet=true;
		this.returnValue = returnValue;
	}
	
	public boolean hasReturnValue(){
		return returnValueSet;
	}
}
