package org.adorsys.plh.pkix.workbench.account.utils;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Text;

public abstract class ValidtionUtils {
	private static EmailValidator emailValidator = new EmailValidator();
	
	public static boolean isComboNotEmpty(Combo combo){
		return combo!=null && StringUtils.isNotBlank(combo.getText());
	}
	
	public static boolean isTextNotEmpty(Text text){
		return text!=null && StringUtils.isNotBlank(text.getText());
	}
	
	public static boolean isNotEmptyAndIdentical(Text text1, Text text2){
		if(!isTextNotEmpty(text1) || !isTextNotEmpty(text2)) return false;
		String text1String = text1.getText();
		String text2String = text2.getText();
		return !StringUtils.equals(text1String, text2String);
	}

	public static boolean validateEmail(String email){
		return emailValidator.isValid(email);
	}
}
