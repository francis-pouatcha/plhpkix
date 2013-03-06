package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

public class OutgoingCertificationRequestHandle {

	private final Date sending;
	private final BigInteger certReqId;
	private final String fileName;
	private final Date sent;
	private final String status;
	
	public OutgoingCertificationRequestHandle(BigInteger certReqId, 
			Date sending, Date sent, String status) {
		super();
		this.sending = sending;
		this.certReqId = certReqId;
		this.fileName = OutgoingCertificationRequestFileNameHelper.makeFileName(certReqId, sending, sent, status);
		this.sent=sent;
		this.status = status;
	}
	public OutgoingCertificationRequestHandle(OutgoingCertificationRequest outgoingCertificationRequest) {
		ASN1Integer crId = outgoingCertificationRequest.getCertReqId();
		certReqId = crId.getPositiveValue();
		try {
			DERGeneralizedTime np = outgoingCertificationRequest.getSending();
			sending= np==null?null:np.getDate();
			DERGeneralizedTime d = outgoingCertificationRequest.getSent();
			sent= d==null?null:d.getDate();
			DERIA5String deria5String = outgoingCertificationRequest.getStatus();
			status = deria5String==null?null:deria5String.getString();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = OutgoingCertificationRequestFileNameHelper.makeFileName(certReqId, sending, sent,status);
	}
	public OutgoingCertificationRequestHandle(String fileName) {
		this.fileName = fileName;
		this.certReqId = OutgoingCertificationRequestFileNameHelper.getCertReqId(fileName);
		this.sending=OutgoingCertificationRequestFileNameHelper.getSending(fileName);
		this.sent=OutgoingCertificationRequestFileNameHelper.getSent(fileName);
		this.status = OutgoingCertificationRequestFileNameHelper.getStatus(fileName);
	}
	public Date getSending() {
		return sending;
	}
	public BigInteger getCertReqId() {
		return certReqId;
	}
	public String getFileName() {
		return fileName;
	}
	
	public Date getSent() {
		return sent;
	}

	public String getStatus() {
		return status;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((certReqId == null) ? 0 : certReqId.hashCode());
		result = prime * result
				+ ((fileName == null) ? 0 : fileName.hashCode());
		result = prime * result + ((sending == null) ? 0 : sending.hashCode());
		result = prime * result + ((sent == null) ? 0 : sent.hashCode());
		result = prime * result + ((status == null) ? 0 : status.hashCode());
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
		OutgoingCertificationRequestHandle other = (OutgoingCertificationRequestHandle) obj;
		if (certReqId == null) {
			if (other.certReqId != null)
				return false;
		} else if (!certReqId.equals(other.certReqId))
			return false;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		if (sending == null) {
			if (other.sending != null)
				return false;
		} else if (!sending.equals(other.sending))
			return false;
		if (sent == null) {
			if (other.sent != null)
				return false;
		} else if (!sent.equals(other.sent))
			return false;
		if (status == null) {
			if (other.status != null)
				return false;
		} else if (!status.equals(other.status))
			return false;
		return true;
	}
}
