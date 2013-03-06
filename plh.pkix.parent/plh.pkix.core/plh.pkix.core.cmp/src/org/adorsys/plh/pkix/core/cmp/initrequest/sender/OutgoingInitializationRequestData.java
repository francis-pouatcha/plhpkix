package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class OutgoingInitializationRequestData implements ActionData {

	private OutgoingRequest request;
	
	public OutgoingInitializationRequestData(OutgoingRequest initializationRequest) {
		this.request = initializationRequest;
	}

	public OutgoingInitializationRequestData() {
	}

	public OutgoingRequest getOutgoingRequest() {
		return request;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(request, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		request = OutgoingRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
