package org.adorsys.plh.pkix.workbench.fileviewer;

import java.io.File;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccount;
import org.eclipse.jface.viewers.ITreeContentProvider;
import org.eclipse.jface.viewers.Viewer;

public class FileTreeContentProvider implements ITreeContentProvider {
	
	public void dispose() {
		// TODO Auto-generated method stub

	}

	public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
		// TODO Auto-generated method stub

	}

	public Object[] getElements(Object inputElement) {
		if(inputElement instanceof DeviceAccount){
			return ((DeviceAccount)inputElement).getDeviceAccountDir().getDeviceAccountDir().listFiles();
		}else {
			return new Object[]{};
		}
	}

	public Object[] getChildren(Object parentElement) {
	    return ((File) parentElement).listFiles();
	 }

	public Object getParent(Object element) {
		return ((File) element).getParentFile();
	}

	public boolean hasChildren(Object element) {
		Object[] obj = getChildren(element);
		return obj == null ? false : obj.length > 0;
	}


}
