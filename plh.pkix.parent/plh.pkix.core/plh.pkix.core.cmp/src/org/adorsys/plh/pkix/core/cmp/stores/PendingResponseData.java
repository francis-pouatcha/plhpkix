package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class PendingResponseData implements ActionData {

	private PendingResponse pendingResponse;
	
	public PendingResponseData(PendingResponse pendingResponse) {
		this.pendingResponse = pendingResponse;
	}

	public PendingResponseData() {
	}

	public PendingResponse getPendingResponse() {
		return pendingResponse;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(pendingResponse, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		pendingResponse = PendingResponse.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
