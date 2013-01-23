package org.adorsys.plh.pkix.workbench.services;

import org.eclipse.e4.core.contexts.IEclipseContext;
import org.eclipse.swt.widgets.Shell;

public interface ImportResourceService {
	public String getCategoryName();
	public String getIconURI();
	public String getLabel();
	public void importResource(Shell shell, IEclipseContext context);
}