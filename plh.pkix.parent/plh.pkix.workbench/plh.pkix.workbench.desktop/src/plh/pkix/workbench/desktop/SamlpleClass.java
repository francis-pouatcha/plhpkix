package plh.pkix.workbench.desktop;

import java.io.File;

import javax.inject.Inject;

import org.eclipse.e4.core.internal.contexts.EclipseContext;

public class SamlpleClass {

	@Inject
	public SamlpleClass(EclipseContext context) {
		String absolutePath = new File("").getAbsolutePath();
		boolean startsWith = absolutePath.startsWith("/");
		if(startsWith==true);

	}
}
