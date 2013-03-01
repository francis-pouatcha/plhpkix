package org.adorsys.plh.pkix.core.cmp.stores;

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingResponseHandle {

	private final String transactionID;
	private final Date responseTime;
	private final Date deliveryTime;
	private final String fileName;
	
	public PendingResponseHandle(String transactionID, Date responseTime, Date deliveryTime) {
		this.transactionID = transactionID;
		this.responseTime = responseTime;
		this.deliveryTime=deliveryTime;
		this.fileName = PendingResponseFileNameHelper.makeFileName(transactionID, responseTime, deliveryTime);
	}
	public PendingResponseHandle(PendingResponse pendingResponse) {
		transactionID = pendingResponse.getTransactionID().toString();
		try {
			DERGeneralizedTime rt = pendingResponse.getResponseTime();
			responseTime= rt==null?null:rt.getDate();
			DERGeneralizedTime d = pendingResponse.getDeliveryTime();
			deliveryTime= d==null?null:d.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = PendingResponseFileNameHelper.makeFileName(transactionID, responseTime, deliveryTime);
	}
	public PendingResponseHandle(String fileName) {
		this.fileName = fileName;
		this.transactionID = PendingResponseFileNameHelper.getTransactionID(fileName);
		this.responseTime=PendingResponseFileNameHelper.getResponseTime(fileName);
		this.deliveryTime=PendingResponseFileNameHelper.getDeliveryTime(fileName);
	}

	public String getFileName() {
		return fileName;
	}
	public String getTransactionID() {
		return transactionID;
	}
	public Date getResponseTime() {
		return responseTime;
	}
	public Date getDeliveryTime() {
		return deliveryTime;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((deliveryTime == null) ? 0 : deliveryTime.hashCode());
		result = prime * result
				+ ((fileName == null) ? 0 : fileName.hashCode());
		result = prime * result
				+ ((responseTime == null) ? 0 : responseTime.hashCode());
		result = prime * result
				+ ((transactionID == null) ? 0 : transactionID.hashCode());
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PendingResponseHandle other = (PendingResponseHandle) obj;
		if (deliveryTime == null) {
			if (other.deliveryTime != null)
				return false;
		} else if (!deliveryTime.equals(other.deliveryTime))
			return false;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		if (responseTime == null) {
			if (other.responseTime != null)
				return false;
		} else if (!responseTime.equals(other.responseTime))
			return false;
		if (transactionID == null) {
			if (other.transactionID != null)
				return false;
		} else if (!transactionID.equals(other.transactionID))
			return false;
		return true;
	}
}
