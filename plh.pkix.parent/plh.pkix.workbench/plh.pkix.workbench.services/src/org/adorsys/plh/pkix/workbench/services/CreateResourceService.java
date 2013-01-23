package org.adorsys.plh.pkix.workbench.services;

import org.eclipse.core.resources.IWorkspace;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.e4.core.services.log.Logger;
import org.eclipse.e4.core.services.statusreporter.StatusReporter;
import org.eclipse.swt.widgets.Shell;

public interface CreateResourceService {

	public String getIconURI();

	public String getLabel();
	
	public void createResource(Shell shell, IWorkspace workspace, StatusReporter statusReporter, Logger logger, IProgressMonitor monitor, String resourceName);

}
