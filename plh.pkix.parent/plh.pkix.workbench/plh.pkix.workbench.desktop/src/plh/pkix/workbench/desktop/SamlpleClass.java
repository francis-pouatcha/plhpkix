package plh.pkix.workbench.desktop;

import java.io.File;

import javax.inject.Inject;

import org.eclipse.e4.core.contexts.IEclipseContext;

public class SamlpleClass {

	@Inject
	public SamlpleClass(IEclipseContext context) {
		String absolutePath = new File("").getAbsolutePath();
		boolean startsWith = absolutePath.startsWith("/");
		if(startsWith==true);

	}
}
