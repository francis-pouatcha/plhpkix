package org.adorsys.plh.pkix.core.cmp.registration;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class OutgoingRegistrationRequestData implements ActionData {

	private OutgoingRequest registrationRequest;
	
	public OutgoingRegistrationRequestData(OutgoingRequest registrationRequest) {
		this.registrationRequest = registrationRequest;
	}

	public OutgoingRegistrationRequestData() {
	}

	public OutgoingRequest getOutgoingRequest() {
		return registrationRequest;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(registrationRequest, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		registrationRequest = OutgoingRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
