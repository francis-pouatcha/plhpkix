package org.adorsys.plh.pkix.server.cmp.endentity;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;

public class EndEntityBuilder {

	private Set<X509CertificateHolder> certs = new HashSet<X509CertificateHolder>();

	private String subjectName;

	public EndEntityBuilder addCert(
			X509CertificateHolder cert) {
		certs.add(cert);
		return this;
	}

	public EndEntityBuilder setSubjectName(String subjectName) {
		this.subjectName = subjectName;
		return this;
	}

	public EndEntityHolder build(){
		return new EndEntityHolder(subjectName, certs);
	}
	
}
