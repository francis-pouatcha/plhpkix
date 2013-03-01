package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.store.DateInFileName;

public abstract class PendingRequestFileNameHelper {
	private static final int RADIX=16;
	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(BigInteger certReqId, Date nextPoll, Date disposed){
		return certReqId.toString(RADIX) + FILEPARTSEPARATOR +DateInFileName.toFileName(nextPoll)+ FILEPARTSEPARATOR+DateInFileName.toFileName(disposed);
	}
	
	public static BigInteger getCertReqId(String fileName){
		String substring = fileName.substring(0, fileName.indexOf(FILEPARTSEPARATOR));
		return new BigInteger(substring, RADIX);
	}

	public static Date getNextPoll(String fileName){
		String substring = fileName.substring(fileName.indexOf(FILEPARTSEPARATOR)+1, fileName.lastIndexOf(FILEPARTSEPARATOR));
		return DateInFileName.fromFileName(substring);
	}

	public static Date getDisposed(String fileName){
		String substring = fileName.substring(fileName.lastIndexOf(FILEPARTSEPARATOR)+1, fileName.length());
		return DateInFileName.fromFileName(substring);
	}
}
