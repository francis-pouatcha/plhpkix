package org.adorsys.plh.pkix.core.smime.utils;

import javax.mail.MessagingException;
import javax.mail.Part;

public class PartUtils {
	
	public static String[] getFrom(Part part){
		try {
			return part.getHeader("From");
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public static String[] getSender(Part part){
		try {
			return part.getHeader("Sender");
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
