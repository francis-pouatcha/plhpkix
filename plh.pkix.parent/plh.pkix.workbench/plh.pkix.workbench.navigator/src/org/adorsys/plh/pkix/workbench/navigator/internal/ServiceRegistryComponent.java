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

import org.adorsys.plh.pkix.workbench.services.CreateResourceService;
import org.adorsys.plh.pkix.workbench.services.ImportResourceService;
import java.util.Vector;

public class ServiceRegistryComponent {
	private Vector<CreateResourceService> creators = new Vector<CreateResourceService>();
	private Vector<ImportResourceService> importServices = new Vector<ImportResourceService>();
	
	public void addCreateResourceService( CreateResourceService creator ) {
		creators.add(creator);
	}
	
	public void removeCreateResourceService(CreateResourceService creator) {
		creators.remove(creator);
	}
	
	public Vector<CreateResourceService> getCreators() {
		return creators;
	}
	
	public void addImportService(ImportResourceService importService) {
		importServices.add(importService);
	}
	
	public void removeImportService(ImportResourceService importService) {
		importServices.remove(importService);
	}
	
	public Vector<ImportResourceService> getImportServices() {
		return importServices;
	}
}
