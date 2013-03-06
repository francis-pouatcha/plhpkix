package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class IncomingInitializationRequestData implements ActionData {

	private IncomingRequest request;
	
	public IncomingInitializationRequestData(IncomingRequest initializationRequest) {
		this.request = initializationRequest;
	}

	public IncomingInitializationRequestData() {
	}

	public IncomingRequest getIncomingRequest() {
		return request;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(request, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		request = IncomingRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
