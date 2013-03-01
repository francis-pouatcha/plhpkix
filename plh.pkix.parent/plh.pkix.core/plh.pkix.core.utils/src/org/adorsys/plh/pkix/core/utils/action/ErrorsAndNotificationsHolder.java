package org.adorsys.plh.pkix.core.utils.action;

import java.util.List;

import org.bouncycastle.i18n.ErrorBundle;

public interface ErrorsAndNotificationsHolder {

	public void addError(ErrorBundle errorBundle);

	public void addNotification(ErrorBundle errorBundle);

	public List<ErrorBundle> getErrors();

	public List<ErrorBundle> getNotifications();
	
	public boolean hasError();
	
	public boolean hasNotification();
	
	public void addErrors(List<ErrorBundle> in);

	public void addNotifications(List<ErrorBundle> in);
}
