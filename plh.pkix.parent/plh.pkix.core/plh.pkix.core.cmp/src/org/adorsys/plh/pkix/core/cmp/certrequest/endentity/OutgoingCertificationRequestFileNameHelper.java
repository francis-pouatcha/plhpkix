package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.math.BigInteger;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.store.DateInFileName;

public abstract class OutgoingCertificationRequestFileNameHelper {
	private static final int RADIX=16;
	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(BigInteger certReqId, Date sending, Date sent, String status){
		return certReqId.toString(RADIX) + FILEPARTSEPARATOR +DateInFileName.toFileName(sending)+ FILEPARTSEPARATOR+DateInFileName.toFileName(sent)+ FILEPARTSEPARATOR+status;
	}
	
	public static BigInteger getCertReqId(String fileName){
		String[] split = fileName.split(FILEPARTSEPARATOR);
		return new BigInteger(split[0], RADIX);
	}

	public static Date getSending(String fileName){
		String[] split = fileName.split(FILEPARTSEPARATOR);
		String substring = split[1];
		return DateInFileName.fromFileName(substring);
	}

	public static Date getSent(String fileName){
		String[] split = fileName.split(FILEPARTSEPARATOR);
		String substring = split[2];
		return DateInFileName.fromFileName(substring);
	}

	public static String getStatus(String fileName){
		String[] split = fileName.split(FILEPARTSEPARATOR);
		return split[3];
	}
}
