/*******************************************************************************
 * Copyright (c) 2010 BestSolution.at and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Tom Schindl <tom.schindl@bestsolution.at> - initial API and implementation
 ******************************************************************************/
package org.adorsys.plh.pkix.workbench.navigator.internal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.adorsys.plh.pkix.workbench.services.ImportResourceService;
import org.eclipse.core.commands.Command;
import org.eclipse.core.commands.ParameterizedCommand;
import org.eclipse.core.databinding.observable.IObservable;
import org.eclipse.core.databinding.observable.Observables;
import org.eclipse.core.databinding.observable.Realm;
import org.eclipse.core.databinding.observable.masterdetail.IObservableFactory;
import org.eclipse.core.databinding.observable.set.IObservableSet;
import org.eclipse.core.databinding.observable.set.WritableSet;
import org.eclipse.core.resources.IContainer;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.IResourceChangeEvent;
import org.eclipse.core.resources.IResourceChangeListener;
import org.eclipse.core.resources.IResourceDelta;
import org.eclipse.core.resources.IResourceDeltaVisitor;
import org.eclipse.core.resources.IWorkspace;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.e4.core.commands.ECommandService;
import org.eclipse.e4.core.commands.EHandlerService;
import org.eclipse.e4.core.contexts.IEclipseContext;
import org.eclipse.e4.ui.model.application.MApplication;
import org.eclipse.e4.ui.model.application.descriptor.basic.MPartDescriptor;
import org.eclipse.e4.ui.workbench.modeling.ESelectionService;
import org.eclipse.jface.action.Action;
import org.eclipse.jface.action.IMenuListener;
import org.eclipse.jface.action.IMenuManager;
import org.eclipse.jface.action.MenuManager;
import org.eclipse.jface.databinding.swt.SWTObservables;
import org.eclipse.jface.databinding.viewers.ObservableSetTreeContentProvider;
import org.eclipse.jface.databinding.viewers.TreeStructureAdvisor;
import org.eclipse.jface.viewers.IOpenListener;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.OpenEvent;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.StructuredSelection;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.jface.viewers.ViewerSorter;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Shell;

public class ResourceNavigator {
	
	  private Map<IContainer, IObservableSet> observableSets = new HashMap<IContainer, IObservableSet>();
	
	@Inject
	private ECommandService commandService;
	
	@Inject
	private EHandlerService handlerService;

	private IResourceChangeListener listener = new IResourceChangeListener() {
		public void resourceChanged(IResourceChangeEvent event) {
			if (event.getType() == IResourceChangeEvent.POST_CHANGE) {
				try {
					event.getDelta().accept(new IResourceDeltaVisitor() {
						public boolean visit(IResourceDelta delta)
								throws CoreException {
							if (delta.getKind() == IResourceDelta.ADDED) {
								handleChange(delta.getResource(), delta
										.getResource().getParent(), true);
							} else if (delta.getKind() == IResourceDelta.REMOVED) {
								handleChange(delta.getResource(), delta
										.getResource().getParent(), false);
							}
							return true;
						}

						private void handleChange(final IResource resource,
								final IContainer parent, final boolean added) {
							final IObservableSet set = observableSets
									.get(parent);
							Realm realm = set != null ? set.getRealm() : null;
							if (realm != null) {
								realm.asyncExec(new Runnable() {
									public void run() {
										if (added) {
											set.add(resource);
										} else {
											set.remove(resource);
										}
									}
								});
							}
						}
					});
				} catch (CoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	};

	private IEclipseContext context;

	@Inject
	private ServiceRegistryComponent serviceRegistry;

	@Inject
	private MApplication application;
	
	@Inject
	private ESelectionService selectionService;
	
	@Inject
	public ResourceNavigator(Composite parent, final IEclipseContext context, IWorkspace workspace) {
		final Realm realm = SWTObservables.getRealm(parent.getDisplay());
		this.context = context;
		parent.setLayout(new FillLayout());
		TreeViewer viewer = new TreeViewer(parent,SWT.FULL_SELECTION|SWT.H_SCROLL|SWT.V_SCROLL);
		viewer.addSelectionChangedListener(new ISelectionChangedListener(){
			public void selectionChanged(SelectionChangedEvent event) {
				StructuredSelection selection = (StructuredSelection)event.getSelection();
				selectionService.setSelection(selection.size() == 1 ? selection.getFirstElement() : selection.toArray());
//				context.modify(IServiceConstants.ACTIVE_SELECTION, selection.size() == 1 ? selection.getFirstElement() : selection.toArray());
			}
		});
		
		IObservableFactory setFactory = new IObservableFactory() {
			public IObservable createObservable(Object element) {
				if (element instanceof IContainer
						&& ((IContainer) element).exists()) {
					IObservableSet observableSet = observableSets.get(element);
					if (observableSet == null) {
						observableSet = new WritableSet(realm);
						try {
							observableSet.addAll(Arrays
									.asList(((IContainer) element).members()));
						} catch (CoreException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						observableSets.put((IContainer) element, observableSet);
					}
					return observableSet;
				}
				return Observables.emptyObservableSet();
			}
		};
		viewer.setContentProvider(new ObservableSetTreeContentProvider(
				setFactory, new TreeStructureAdvisor() {
					public Boolean hasChildren(Object element) {
						return Boolean.valueOf(element instanceof IContainer);
					}
				}));

		viewer.setLabelProvider(new LabelProvider() {
			public String getText(Object element) {
				if (element instanceof IResource)
					return ((IResource) element).getName();
				return element == null ? "" : element.toString();
			}
		});
		viewer.setSorter(new ViewerSorter());
		viewer.setInput(workspace.getRoot());
		viewer.addOpenListener(new IOpenListener() {
			
			public void open(OpenEvent event) {
				IStructuredSelection s = (IStructuredSelection) event.getSelection();
				for( Object o : s.toArray() ) {
					if( o instanceof IFile ) {
						IFile f = (IFile) o;
						context.set(IFile.class, f);
						String fExt = f.getFileExtension();
						EDITOR: for( MPartDescriptor desc : application.getDescriptors() ) {
							String category = desc.getCategory();
							if(category==null)continue;
							String[] categories = category.split(",");
							for( String ext: categories ) {
								if( ext.equalsIgnoreCase(fExt) ) {
									context.set(MPartDescriptor.class, desc);
									System.err.println("Opening with: " + desc);
									Command cmd = commandService.getCommand("desktop.command.openeditor");
									ParameterizedCommand pCmd = ParameterizedCommand.generateCommand(cmd, null);
									handlerService.executeHandler(pCmd);
									
									break EDITOR;
								}
							}
						}
					}
				}
				
			}
		});
		setupContextMenu(viewer, parent.getShell());
		workspace.addResourceChangeListener(listener);
	}
	
	private void setupContextMenu(final TreeViewer viewer, final Shell shell) {
		MenuManager mgr = new MenuManager();
		viewer.getControl().setMenu(mgr.createContextMenu(viewer.getControl()));
		
		mgr.setRemoveAllWhenShown(true);
		mgr.addMenuListener(new IMenuListener() {
			
			public void menuAboutToShow(IMenuManager manager) {
				MenuManager mgr = new MenuManager("Import");
				for( ImportResourceService s : serviceRegistry.getImportServices() ) {
					final ImportResourceService tmp = s;
					Action a = new Action(s.getLabel()) {
						public void run() {
							tmp.importResource(shell, context.createChild());
						}
					};
					mgr.add(a);
				}
				
				manager.add(mgr);
			}
		});
	}
}