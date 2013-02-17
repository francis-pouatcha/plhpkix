package org.adorsys.plh.pkix.workbench.fileviewer;

import java.io.File;
import java.net.URL;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccount;
import org.adorsys.plh.pkix.client.sedent.identity.UserAccount;
import org.eclipse.core.runtime.FileLocator;
import org.eclipse.core.runtime.Path;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.graphics.Image;
import org.osgi.framework.Bundle;
import org.osgi.framework.FrameworkUtil;

public class FileLabelProvider extends LabelProvider {

	private static final Image FOLDER = getImage("folder.gif");
	private static final Image FILE = getImage("file.gif");

	private DeviceAccount deviceAccount;
	private UserAccount userAccount;
	
	@Override
	public Image getImage(Object element) {
		if (((File) element).isDirectory())
			return FOLDER;
		return FILE;
	}

	@Override
	public String getText(Object element) {
		if (element == null)
			return "";
		return ((File) element).getName();
	}

	// Helper Method to load the images
	private static Image getImage(String file) {
		Bundle bundle = FrameworkUtil.getBundle(FileLabelProvider.class);
		URL url = FileLocator.find(bundle, new Path("icons/" + file), null);
		ImageDescriptor image = ImageDescriptor.createFromURL(url);
		return image.createImage();

	}
}
