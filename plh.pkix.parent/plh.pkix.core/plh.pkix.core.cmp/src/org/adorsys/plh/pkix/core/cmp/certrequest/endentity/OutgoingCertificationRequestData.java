package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class OutgoingCertificationRequestData implements ActionData {

	private OutgoingCertificationRequest certificationRequest;
	
	public OutgoingCertificationRequestData(OutgoingCertificationRequest certificationRequest) {
		this.certificationRequest = certificationRequest;
	}

	public OutgoingCertificationRequestData() {
	}

	public OutgoingCertificationRequest getOutgoingCertificationRequest() {
		return certificationRequest;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(certificationRequest, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		certificationRequest = OutgoingCertificationRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
