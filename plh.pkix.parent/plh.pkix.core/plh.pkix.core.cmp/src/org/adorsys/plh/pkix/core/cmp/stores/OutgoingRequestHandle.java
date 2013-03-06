package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

public class OutgoingRequestHandle {

	private final Date nextAction;
	private final BigInteger certReqId;
	private final String fileName;
	private final Date disposed;
	private final String status;
	
	public OutgoingRequestHandle(BigInteger certReqId, 
			Date nextAction, Date disposed, String status) {
		super();
		this.nextAction = nextAction;
		this.certReqId = certReqId;
		this.disposed=disposed;
		this.status = status;
		this.fileName = OutgoingRequestFileNameHelper.makeFileName(certReqId, nextAction, status, disposed);
	}
	public OutgoingRequestHandle(
			OutgoingRequest outgoingRequest) {
		ASN1Integer crId = outgoingRequest.getCertReqId();
		certReqId = crId.getPositiveValue();
		try {
			DERGeneralizedTime np = outgoingRequest.getNextPoll();
			nextAction= np==null?null:np.getDate();
			DERGeneralizedTime d = outgoingRequest.getDisposed();
			disposed= d==null?null:d.getDate();
			DERIA5String deria5String = outgoingRequest.getStatus();
			status = deria5String==null?null:deria5String.getString();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = OutgoingRequestFileNameHelper.makeFileName(certReqId, nextAction,status, disposed);
	}
	public OutgoingRequestHandle(String fileName) {
		this.fileName = fileName;
		String[] nameComponents = OutgoingRequestFileNameHelper.getNameComponents(fileName);
		this.certReqId = OutgoingRequestFileNameHelper.getCertReqId(nameComponents);
		this.nextAction=OutgoingRequestFileNameHelper.getNextAction(nameComponents);
		this.disposed=OutgoingRequestFileNameHelper.getDisposed(nameComponents);
		this.status = OutgoingRequestFileNameHelper.getStatus(nameComponents);
	}
	public Date getNextAction() {
		return nextAction;
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
		OutgoingRequestHandle other = (OutgoingRequestHandle) obj;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		return true;
	}
//	
//	public static final OutgoingRequestHandle makeHandle(OutgoingRequest outgoingRequest){
//		DERGeneralizedTime nextActionGT = outgoingRequest.getNextPoll();
//		Date nextACtion = null;
//		if(nextActionGT!=null)
//			try {
//				nextACtion = nextActionGT.getDate();
//			} catch (ParseException e) {
//				throw new IllegalStateException(e);
//			}
//		DERGeneralizedTime disposedGT = outgoingRequest.getDisposed();
//		Date disposed=null;
//		if(disposedGT!=null)
//			try {
//				disposed = disposedGT.getDate();
//			} catch (ParseException e) {
//				throw new IllegalStateException(e);
//			}
//		DERIA5String statusIAS = outgoingRequest.getStatus();
//		String status = statusIAS==null?null:statusIAS.getString();
//		return new OutgoingRequestHand
////		if(outgoingRequestHandles.containsKey(certReqId)){
////			deleteRequest(certReqId);
////		}
//		
//	}
}
