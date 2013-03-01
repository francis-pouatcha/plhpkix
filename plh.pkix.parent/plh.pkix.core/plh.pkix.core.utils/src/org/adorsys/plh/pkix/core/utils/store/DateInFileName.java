package org.adorsys.plh.pkix.core.utils.store;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class DateInFileName {
	private static final String NULL_STRING="null";
	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmssSSSZ");

	public static String toFileName(Date date){
		if(date==null) return NULL_STRING;
		return dateFormat.format(date);
	}
	
	public static Date fromFileName(String fileName){
		if(NULL_STRING.equalsIgnoreCase(fileName)) return null;
		try {
			return dateFormat.parse(fileName);
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
