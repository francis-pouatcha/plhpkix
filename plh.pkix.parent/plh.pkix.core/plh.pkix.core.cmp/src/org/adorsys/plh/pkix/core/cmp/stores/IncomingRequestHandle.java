package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

public class IncomingRequestHandle {

	private final Date lastRequest;
	private final BigInteger certReqId;
	private final String fileName;
	private final Date disposed;
	private final String status;
	
	public IncomingRequestHandle(BigInteger certReqId, 
			Date lastRequest, Date disposed, String status) {
		super();
		this.lastRequest = lastRequest;
		this.certReqId = certReqId;
		this.disposed=disposed;
		this.status = status;
		this.fileName = IncomingRequestFileNameHelper.makeFileName(certReqId, lastRequest, status, disposed);
	}
	public IncomingRequestHandle(
			IncomingRequest incomingRequest) {
		ASN1Integer crId = incomingRequest.getCertReqId();
		certReqId = crId.getPositiveValue();
		try {
			DERGeneralizedTime np = incomingRequest.getLastRequest();
			lastRequest= np==null?null:np.getDate();
			DERGeneralizedTime d = incomingRequest.getDisposed();
			disposed= d==null?null:d.getDate();
			DERIA5String deria5String = incomingRequest.getStatus();
			status = deria5String==null?null:deria5String.getString();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = IncomingRequestFileNameHelper.makeFileName(certReqId, lastRequest,status, disposed);
	}
	public IncomingRequestHandle(String fileName) {
		this.fileName = fileName;
		String[] nameComponents = IncomingRequestFileNameHelper.getNameComponents(fileName);
		this.certReqId = IncomingRequestFileNameHelper.getCertReqId(nameComponents);
		this.lastRequest=IncomingRequestFileNameHelper.getLastRequest(nameComponents);
		this.disposed=IncomingRequestFileNameHelper.getDisposed(nameComponents);
		this.status = IncomingRequestFileNameHelper.getStatus(nameComponents);
	}
	public Date getLastRequest() {
		return lastRequest;
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

	public String getStatus() {
		return status;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((fileName == null) ? 0 : fileName.hashCode());
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
		IncomingRequestHandle other = (IncomingRequestHandle) obj;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		return true;
	}
}
