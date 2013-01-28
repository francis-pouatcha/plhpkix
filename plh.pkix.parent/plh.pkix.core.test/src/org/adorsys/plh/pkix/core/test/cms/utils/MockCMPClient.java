package org.adorsys.plh.pkix.core.test.cms.utils;

import java.util.List;

import javax.mail.internet.AddressException;

import org.adorsys.plh.pkix.core.CMPClient;
import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;

public class MockCMPClient implements CMPClient {
	
	private PrivateKeyHolder privateKeyHolder = new PrivateKeyHolder();
	private CertificateStore certificateStore = new CertificateStore();
	private CryptoClient cryptoClient;
	
	@Override
	public void register(String name, String email) {

		String uniqueIde;
		try {
			uniqueIde = X500NameHelper.parseEmailAddress(email);
		} catch (AddressException e) {
			throw new IllegalArgumentException(e);
		}
		X500Name x500Name = new X500NameBuilder(BCStyle.INSTANCE)
			.addRDN(BCStyle.UnstructuredName, name)
			.addRDN(BCStyle.EmailAddress, email)
			.addRDN(BCStyle.UNIQUE_IDENTIFIER, uniqueIde)
			.build();
		cryptoClient = new CryptoClient(x500Name,privateKeyHolder, certificateStore);
	}

	@Override
	public void requestCertification(X500Name certAuthorityName,
			X509CertificateHolder model) {
		// TODO Auto-generated method stub

	}

	@Override
	public void fetchCertificate(X500Name subjectName,
			List<X500Name> certAuthorityName) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<X509CertificateHolder> listCertificationRequests() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void certify(X509CertificateHolder certificationRequest) {
		// TODO Auto-generated method stub

	}

	@Override
	public void reject(X509CertificateHolder certificationRequest) {
		// TODO Auto-generated method stub

	}

}
