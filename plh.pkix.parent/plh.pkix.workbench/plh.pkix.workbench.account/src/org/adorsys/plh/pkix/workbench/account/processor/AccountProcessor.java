package org.adorsys.plh.pkix.workbench.account.processor;

import java.io.File;
import java.net.URL;

import javax.inject.Inject;
import javax.inject.Named;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountRootDir;
import org.eclipse.e4.core.contexts.IEclipseContext;
import org.eclipse.e4.core.di.annotations.Execute;
import org.eclipse.e4.ui.internal.workbench.E4Workbench;
import org.eclipse.osgi.service.datalocation.Location;

/**
 * The account processor will check if an account exists. If not, it
 * will activate the registration screen to collect the user's email.
 * 
 * @author francis
 *
 */
@SuppressWarnings("restriction")
public class AccountProcessor {

	@Inject
	@Named(E4Workbench.INSTANCE_LOCATION)
	private Location instanceLocation;		

	@Inject
	IEclipseContext context;

	@Execute
	public void execute(){
		URL url = instanceLocation.getURL();
		File file = new File(url.getPath());
		DeviceAccountRootDir deviceDir = new DeviceAccountRootDir(file.getAbsolutePath());
		context.set(DeviceAccountRootDir.class, deviceDir);
	}
}
