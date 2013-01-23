/*******************************************************************************
 * Copyright (c) 2010 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 ******************************************************************************/

package org.adorsys.plh.pkix.workbench.menu;

import javax.inject.Named;
import org.eclipse.e4.core.di.annotations.CanExecute;
import org.eclipse.e4.core.di.annotations.Execute;
import org.eclipse.e4.core.di.annotations.Optional;
import org.eclipse.e4.ui.services.IServiceConstants;

public class OpenDialogHandler {
	@CanExecute
	public boolean canExecute(
			@Named(IServiceConstants.SELECTION) @Optional ContextMenuView.Tag tag) {
		return tag != null;
	}

	@Execute
	public void execute(
			@Named(IServiceConstants.SELECTION) @Optional ContextMenuView.Tag tag) {
		System.out.println(tag.name);
	}
}
