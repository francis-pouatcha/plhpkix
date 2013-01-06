package org.adorys.plh.pkix.server.cmp.core.certann;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class CertificateAnnouncementHolder {

	private final PKIMessage pkiMessage;
	
	public CertificateAnnouncementHolder(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}
}
