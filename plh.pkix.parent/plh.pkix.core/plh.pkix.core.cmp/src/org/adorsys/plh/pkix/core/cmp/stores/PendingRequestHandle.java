package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingRequestHandle {

	private final Date nextPoll;
	private final BigInteger certReqId;
	private final String fileName;
	private final Date disposed;
	
	public PendingRequestHandle(BigInteger certReqId, Date nextPoll, Date disposed) {
		super();
		this.nextPoll = nextPoll;
		this.certReqId = certReqId;
		this.fileName = PendingRequestFileNameHelper.makeFileName(certReqId, nextPoll, disposed);
		this.disposed=disposed;
	}
	public PendingRequestHandle(PendingRequest pendingRequest) {
		ASN1Integer crId = pendingRequest.getCertReqId();
		certReqId = crId.getPositiveValue();
		try {
			DERGeneralizedTime np = pendingRequest.getNextPoll();
			nextPoll= np==null?null:np.getDate();
			DERGeneralizedTime d = pendingRequest.getDisposed();
			disposed= d==null?null:d.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = PendingRequestFileNameHelper.makeFileName(certReqId, nextPoll, disposed);
	}
	public PendingRequestHandle(String fileName) {
		this.fileName = fileName;
		this.certReqId = PendingRequestFileNameHelper.getCertReqId(fileName);
		this.nextPoll=PendingRequestFileNameHelper.getNextPoll(fileName);
		this.disposed=PendingRequestFileNameHelper.getDisposed(fileName);
	}
	public Date getNextPoll() {
		return nextPoll;
	}
	public BigInteger getCertReqId() {
		return certReqId;
	}
	public String getFileName() {
		return fileName;
	}
	
	public Date getDisposed() {
		return disposed;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((certReqId == null) ? 0 : certReqId.hashCode());
		result = prime * result
				+ ((disposed == null) ? 0 : disposed.hashCode());
		result = prime * result
				+ ((fileName == null) ? 0 : fileName.hashCode());
		result = prime * result
				+ ((nextPoll == null) ? 0 : nextPoll.hashCode());
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
		PendingRequestHandle other = (PendingRequestHandle) obj;
		if (certReqId == null) {
			if (other.certReqId != null)
				return false;
		} else if (!certReqId.equals(other.certReqId))
			return false;
		if (disposed == null) {
			if (other.disposed != null)
				return false;
		} else if (!disposed.equals(other.disposed))
			return false;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		if (nextPoll == null) {
			if (other.nextPoll != null)
				return false;
		} else if (!nextPoll.equals(other.nextPoll))
			return false;
		return true;
	}	
}
