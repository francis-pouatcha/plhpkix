package org.adorsys.plh.pkix.workbench.test.account.register.dialogs;

import org.adorsys.plh.pkix.workbench.account.register.dialogs.RegisterView;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;

@SuppressWarnings("all")
public class RegisterViewMain {

	public static void main(String[] args) {

		Display display = new Display();
		Shell shell = new Shell(display, SWT.CLOSE | SWT.BORDER | SWT.TITLE);
		
		new RegisterView(shell);
		
		shell.setSize(400, 400);
		shell.open();
		
		while(!shell.isDisposed()){
			if(!display.readAndDispatch())
				display.sleep();
		}
		display.dispose();		
	}

}
