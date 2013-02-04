package org.adorsys.plh.pkix.workbench.account.utils;


import java.util.regex.Matcher;

public class EmailValidator {
	private static String ATOM = "[a-z0-9!#$%&'*+/=?^_`{|}~-]";
	private static String DOMAIN = "(" + ATOM + "+(\\." + ATOM + "+)*";
	private static String IP_DOMAIN = "\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\]";

	private java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
			"^" + ATOM + "+(\\." + ATOM + "+)*@"
					+ DOMAIN
					+ "|"
					+ IP_DOMAIN
					+ ")$",
			java.util.regex.Pattern.CASE_INSENSITIVE
	);

	public boolean isValid(String value) {
		if ( value == null || value.length() == 0 ) {
			return true;
		}
		Matcher m = pattern.matcher( value );
		return m.matches();
	}
}
