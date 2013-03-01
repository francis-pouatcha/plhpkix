package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.Date;

import org.adorsys.plh.pkix.core.utils.store.DateInFileName;

public abstract class PendingResponseFileNameHelper {
	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(String transactionID, Date responseTime, Date deliveryTime){
		return transactionID + FILEPARTSEPARATOR +DateInFileName.toFileName(responseTime)+ FILEPARTSEPARATOR+DateInFileName.toFileName(deliveryTime);
	}
	
	public static String getTransactionID(String fileName){
		return fileName.substring(0, fileName.indexOf(FILEPARTSEPARATOR));
	}

	public static Date getResponseTime(String fileName){
		String substring = fileName.substring(fileName.indexOf(FILEPARTSEPARATOR)+1, fileName.lastIndexOf(FILEPARTSEPARATOR));
		return DateInFileName.fromFileName(substring);
	}

	public static Date getDeliveryTime(String fileName){
		String substring = fileName.substring(fileName.lastIndexOf(FILEPARTSEPARATOR)+1, fileName.length());
		return DateInFileName.fromFileName(substring);
	}
}
