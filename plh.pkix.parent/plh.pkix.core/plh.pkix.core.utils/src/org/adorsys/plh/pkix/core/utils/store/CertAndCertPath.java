package org.adorsys.plh.pkix.core.utils.store;

import org.bouncycastle.cert.X509CertificateHolder;

public class CertAndCertPath {

	private final X509CertificateHolder certHolder;
	private final CertPathAndOrigin certPathAndOrigin;
	public CertAndCertPath(X509CertificateHolder certHolder,
			CertPathAndOrigin certPathAndOrigin) {
		super();
		this.certHolder = certHolder;
		this.certPathAndOrigin = certPathAndOrigin;
	}
	public X509CertificateHolder getCertHolder() {
		return certHolder;
	}
	public CertPathAndOrigin getCertPathAndOrigin() {
		return certPathAndOrigin;
	}
	
}
