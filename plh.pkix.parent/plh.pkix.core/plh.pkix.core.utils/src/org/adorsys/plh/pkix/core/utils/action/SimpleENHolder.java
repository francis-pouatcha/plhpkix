package org.adorsys.plh.pkix.core.utils.action;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.i18n.ErrorBundle;

public class SimpleENHolder implements ErrorsAndNotificationsHolder {

	private List<ErrorBundle> errors = new ArrayList<ErrorBundle>();

	private List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();
	
	@Override
	public void addError(ErrorBundle errorBundle) {
		errors.add(errorBundle);
	}

	@Override
	public void addNotification(ErrorBundle errorBundle) {
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
	public boolean hasError() {
		return !errors.isEmpty();
	}

	@Override
	public boolean hasNotification() {
		return !notifications.isEmpty();
	}

	@Override
	public void addErrors(List<ErrorBundle> in) {
		errors.addAll(in);
	}

	@Override
	public void addNotifications(List<ErrorBundle> in) {
		notifications.addAll(in);
	}

}
