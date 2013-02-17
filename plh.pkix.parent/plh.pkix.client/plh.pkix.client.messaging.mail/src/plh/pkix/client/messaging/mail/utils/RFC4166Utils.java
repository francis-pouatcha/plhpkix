package plh.pkix.client.messaging.mail.utils;

import java.util.Locale;

import org.apache.commons.lang3.StringUtils;

public class RFC4166Utils {
	public static Locale getLocale(String rfcString){
		if (StringUtils.isBlank(rfcString)) return Locale.US;
		String[] split = rfcString.split("-");
		if (split.length<1) return Locale.US;
		if (split.length==1 ) return new Locale(rfcString);
		if (split.length==2 ) return new Locale(split[0],split[1]);
		return new Locale(split[0],split[1],split[2]);
	}
	
	public static String toRfc4166String(Locale locale){
		if(locale==null)return null;
		String language = locale.getLanguage();
		String country = locale.getCountry();
		String variant = locale.getVariant();
		if (StringUtils.isBlank(language)){
			return locale.toString();
		}
		String result = language;
		if (StringUtils.isNotBlank(country)){
			result += "-"+country;
		}
		if(StringUtils.isNotBlank(variant)){
			result += "-"+variant;
		}
		return result;
	}
}
