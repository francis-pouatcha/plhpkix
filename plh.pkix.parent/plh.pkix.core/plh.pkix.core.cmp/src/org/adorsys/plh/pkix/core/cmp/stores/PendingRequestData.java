package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class PendingRequestData implements ActionData {

	private PendingRequest pendingRequest;
	
	public PendingRequestData(PendingRequest pendingRequest) {
		this.pendingRequest = pendingRequest;
	}

	public PendingRequestData() {
	}

	public PendingRequest getPendingRequest() {
		return pendingRequest;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(pendingRequest, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		pendingRequest = PendingRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
