package org.adorsys.plh.pkix.core.cmp.stores;

import java.text.ParseException;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.store.DateInFileName;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class CMPRequestFileNameHelper {
	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(String transactionID, Date created, String objectType){
		return transactionID + FILEPARTSEPARATOR +
				DateInFileName.toFileName(created)+ FILEPARTSEPARATOR+
				objectType;
	}
	public static String makeFileName(CMPRequest cmpRequest){
		return makeFileName(cmpRequest.getTransactionID(), cmpRequest.getCreated());
	}
	public static String makeFileName(ASN1OctetString transactionID, DERGeneralizedTime created){
		String hexEncodedTxId = KeyIdUtils.hexEncode(transactionID);
		Date createUtilDate;
		try {
			createUtilDate = created.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		return new StringBuilder(hexEncodedTxId)
			.append(FILEPARTSEPARATOR)
			.append(DateInFileName.toFileName(createUtilDate))
			.toString();
	}

	public static String getTransactionID(String[] nameComponents){
		return nameComponents[0];
	}

	public static Date getCreated(String[] nameComponents){
		String substring = nameComponents[1];
		return DateInFileName.fromFileName(substring);
	}

	public static String[] getNameComponents(String fileName){
		return fileName.split(FILEPARTSEPARATOR);
	}
	
	public static String getTransactionID(String fileName){
		return getTransactionID(getNameComponents(fileName));
	}

	public static Date getCreated(String fileName){
		return getCreated(getNameComponents(fileName));
	}
	
	public static String getTransactionID(ASN1OctetString transactionID){
		return KeyIdUtils.hexEncode(transactionID) + FILEPARTSEPARATOR;
	}
	
	public static String find(String[] children,  ASN1OctetString transactionID){
		String txid = getTransactionID(transactionID);
		for (String fileName : children) {
			if(StringUtils.startsWithIgnoreCase(fileName, txid)) return fileName;
		}
		return null;
	}
}
