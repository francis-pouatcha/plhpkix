package org.adorsys.plh.pkix.workbench.account.register.dialogs;

import org.eclipse.osgi.util.NLS;

public class Messages extends NLS {
	private static final String BUNDLE_NAME = "OSGI-INF/l10n/bundle";
	
	public static String Register_dialog_cancel;
	public static String Register_dialog_done;
	public static String Register_dialog_register;
	public static String Register_dialog_password;
	public static String Register_dialog_repeat_password;
	public static String Register_dialog_email;
	public static String Register_dialog_title;
	public static String Register_dialog_email_exists;
	public static String Register_dialog_both_passwords_not_identical;

	static {
		NLS.initializeMessages(BUNDLE_NAME, Messages.class);
	}
}
