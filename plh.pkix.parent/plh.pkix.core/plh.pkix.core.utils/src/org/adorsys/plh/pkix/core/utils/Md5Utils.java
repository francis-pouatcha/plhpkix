package org.adorsys.plh.pkix.core.utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang3.StringUtils;

public class Md5Utils {
	
	public static String toMd5StringHex(String str){
		if(StringUtils.isBlank(str)) throw new IllegalArgumentException("str is blank");
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
			byte[] digest = messageDigest.digest(str.getBytes("UTF-8"));
			return new BigInteger(1, digest).toString(16);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
}
