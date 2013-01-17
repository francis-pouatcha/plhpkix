package org.adorys.plh.pkix.core.cmp.initrequest;

import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class InitializationResponseProcessor {

	private CertificateStore certificateStore;

	public void process(CertTemplate certTemplate,
			ProtectedPKIMessage protectedPKIMessage) {

		assert certificateStore!=null : "Field certificateStore can not be null";
		
		PKIBody pkiBody = protectedPKIMessage.getBody();
		CertRepMessage certRepMessage = CertRepMessage.getInstance(pkiBody
				.getContent());
		CMPCertificate[] caPubs = certRepMessage.getCaPubs();

		X500Name subject = certTemplate.getSubject();
		X500Name issuer = certTemplate.getIssuer();
		SubjectPublicKeyInfo publicKey = certTemplate.getPublicKey();

		for (CMPCertificate cmpCertificate : caPubs) {
			Certificate x509v3pkCert = cmpCertificate.getX509v3PKCert();

			if (subject != null && !subject.equals(x509v3pkCert.getSubject()))
				continue;

			if (issuer != null && !issuer.equals(x509v3pkCert.getIssuer()))
				continue;

			if (publicKey != null && !publicKey
							.equals(x509v3pkCert.getSubjectPublicKeyInfo()))
				continue;

			certificateStore.addCertificate(new X509CertificateHolder(
					x509v3pkCert));
		}
	}

	public InitializationResponseProcessor setCertificateStore(CertificateStore certificateStore) {
		this.certificateStore = certificateStore;
		return this;
	}
}
