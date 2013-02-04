package org.adorsys.plh.pkix.workbench.account.utils;

import org.eclipse.osgi.util.NLS;

public class AccountMessages extends NLS {
	private static final String BUNDLE_NAME = "OSGI-INF/l10n/bundle";




	public static String Register_dialog_cancel;
	public static String Register_dialog_done;
	public static String Register_dialog_register;
	public static String Register_dialog_protectionQuestion;
	public static String Register_dialog_protectionAnswer;
	public static String Register_dialog_repeatProtectionAnswer;
	public static String Register_dialog_email;
	public static String Register_dialog_title;
	public static String Register_dialog_email_exists;
	public static String Register_dialog_both_protectionAnswers_not_identical;
	public static String Register_dialog_enableProtection;
	public static String Register_dialog_invalide_email;
	public static String Register_dialog_confirm_address;

	public static String Select_dialog_email;
	public static String Select_dialog_title;
	public static String Select_dialog_login;
	public static String Select_dialog_protectionQuestion;
	public static String Select_dialog_protectionAnswer;
	
	
	static {
		NLS.initializeMessages(BUNDLE_NAME, AccountMessages.class);
	}
}
