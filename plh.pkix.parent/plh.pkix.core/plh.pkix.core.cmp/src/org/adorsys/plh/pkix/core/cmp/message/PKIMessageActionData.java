package org.adorsys.plh.pkix.core.cmp.message;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class PKIMessageActionData implements ActionData {
	private PKIMessage pkiMessage;

	public PKIMessageActionData(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}
	
	public PKIMessageActionData() {
		super();
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(pkiMessage, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		ASN1StreamUtils.readFrom(inputStream);
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}
}
