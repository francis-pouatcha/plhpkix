package org.adorys.plh.pkix.server.cmp.core.initrequest;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertTemplate;

public class InitializationRequestHolder {

	private final PKIMessage pkiMessage;
    private final CertTemplate certTemplate;

	public InitializationRequestHolder(PKIMessage pkiMessage,
			CertTemplate certTemplate) {
		super();
		this.pkiMessage = pkiMessage;
		this.certTemplate = certTemplate;
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}

	public CertTemplate getCertTemplate() {
		return certTemplate;
	}
}
