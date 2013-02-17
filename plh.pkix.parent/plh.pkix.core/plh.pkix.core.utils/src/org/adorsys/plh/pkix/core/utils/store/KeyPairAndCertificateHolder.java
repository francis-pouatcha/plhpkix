package org.adorsys.plh.pkix.core.utils.store;

import java.security.KeyPair;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;

public class KeyPairAndCertificateHolder {
	
	private final KeyPair keyPair;
	
	private final X509CertificateHolder subjectCertificateHolder;
	
	private final List<X509CertificateHolder> issuerChain;

	public KeyPairAndCertificateHolder(KeyPair keyPair,
			X509CertificateHolder subjectCertificateHolder,
			List<X509CertificateHolder> issuerChain) {
		super();
		this.keyPair = keyPair;
		this.subjectCertificateHolder = subjectCertificateHolder;
		this.issuerChain = issuerChain;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}

	public X509CertificateHolder getSubjectCertificateHolder() {
		return subjectCertificateHolder;
	}

	public List<X509CertificateHolder> getIssuerChain() {
		return issuerChain;
	}

}
