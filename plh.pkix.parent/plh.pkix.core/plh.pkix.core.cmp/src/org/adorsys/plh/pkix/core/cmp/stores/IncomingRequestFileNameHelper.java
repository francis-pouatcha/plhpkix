package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.store.DateInFileName;

public abstract class IncomingRequestFileNameHelper {
	private static final int RADIX=16;
	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(BigInteger certReqId, Date lastRequest, String status, Date disposed){
		return certReqId.toString(RADIX) + FILEPARTSEPARATOR +DateInFileName.toFileName(lastRequest)+ FILEPARTSEPARATOR+status+ FILEPARTSEPARATOR+DateInFileName.toFileName(disposed);
	}
	
	public static String[] getNameComponents(String fileName){
		return fileName.split(FILEPARTSEPARATOR);
	}
	
	public static BigInteger getCertReqId(String fileName){
		return getCertReqId(getNameComponents(fileName));
	}

	public static Date getLastRequest(String fileName){
		return getLastRequest(getNameComponents(fileName));
	}

	public static Date getDisposed(String fileName){
		return getDisposed(getNameComponents(fileName));
	}

	public static String getStatus(String fileName){
		return getStatus(getNameComponents(fileName));
	}
	
	public static BigInteger getCertReqId(String[] nameComponents){
		return new BigInteger(nameComponents[0], RADIX);
	}

	public static Date getLastRequest(String[] nameComponents){
		String substring = nameComponents[1];
		return DateInFileName.fromFileName(substring);
	}

	public static Date getDisposed(String[] nameComponents){
		String substring = nameComponents[3];
		return DateInFileName.fromFileName(substring);
	}

	public static String getStatus(String[] nameComponents){
		return nameComponents[2];
	}
}
