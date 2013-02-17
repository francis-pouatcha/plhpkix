package org.adorsys.plh.pkix.workbench.fileviewer;

import java.io.File;

import javax.inject.Inject;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountDir;
import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccount;
import org.eclipse.e4.core.di.annotations.Optional;
import org.eclipse.e4.ui.di.Focus;
import org.eclipse.e4.ui.di.UIEventTopic;
import org.eclipse.e4.ui.model.application.ui.basic.MPart;
import org.eclipse.e4.ui.workbench.modeling.EModelService;
import org.eclipse.jface.viewers.DoubleClickEvent;
import org.eclipse.jface.viewers.IDoubleClickListener;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.KeyAdapter;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.widgets.Composite;

@SuppressWarnings("all")
public class FileViewer {
	private TreeViewer viewer;
	private DeviceAccount deviceAccount;

	@Inject @Optional
	void deviceAccountSet(@UIEventTopic(DeviceAccount.TOPIC_NAME) DeviceAccount deviceAccount,
			Composite parent, MPart fileViewerControl, EModelService modelService) {
		this.deviceAccount = deviceAccount;
		if(viewer==null) return;
		// Provide the input to the ContentProvider
		viewer.setInput(deviceAccount);
		createPartControl(parent, fileViewerControl);
		fileViewerControl.setVisible(true);
		modelService.bringToTop(fileViewerControl);
	}
	
	@Inject
	void createPartControl(Composite parent, MPart fileViewerControl) {
		viewer = new TreeViewer(parent, SWT.MULTI | SWT.H_SCROLL | SWT.V_SCROLL);
		viewer.setContentProvider(new FileTreeContentProvider());
		viewer.setLabelProvider(new FileLabelProvider());
		// Expand the tree
		viewer.setAutoExpandLevel(2);

		// Add a doubleclicklistener
		viewer.addDoubleClickListener(
				new IDoubleClickListener() {
					public void doubleClick(DoubleClickEvent event) {
						TreeViewer viewer = (TreeViewer) event.getViewer();
						IStructuredSelection thisSelection = (IStructuredSelection) event
								.getSelection();
						Object selectedNode = thisSelection.getFirstElement();
						viewer.setExpandedState(selectedNode,
								!viewer.getExpandedState(selectedNode));
					}
				}
		);

		viewer.getTree().addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(final KeyEvent e) {
				if (e.keyCode == SWT.DEL) {
					final IStructuredSelection selection = (IStructuredSelection) viewer
							.getSelection();
					if (selection.getFirstElement() instanceof File) {
						File o = (File) selection.getFirstElement();
						// TODO Delete the selected element from the model
					}

				}
			}
		});

	}

	@Focus
	public void setFocus() {
		viewer.getControl().setFocus();
	}
}
